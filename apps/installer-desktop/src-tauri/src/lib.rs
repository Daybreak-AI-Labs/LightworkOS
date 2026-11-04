//! Tauri shell for Lightwork's source bootstrap.
//!
//! The window hosts a one-button Svelte UI. Pressing "Install Lightwork" runs
//! the same bootstrap the CLI one-liners use
//! (`deploy/desktop/install.{ps1,sh}`) with `MAVERICK_NO_WIZARD=1`, and
//! streams each output line to the UI as a Tauri event. No Python is
//! required on the machine first -- the bootstrap installs it. When it
//! finishes, the UI can open the dashboard for in-app setup. The bundle is not
//! self-contained: it clones the pinned commit from GitHub, so network access
//! is required, and the resulting Python source remains readable.
//!
//! Why shell out to the existing scripts instead of reimplementing the
//! install in Rust: those scripts are already tested and handle the
//! gnarly bits (winget/brew/apt, PATH, pipx, PEP 668). The shell stays
//! tiny and there's a single source of truth for "how to install".

mod bootstrap_recovery;

use lightwork_desktop_runtime::{Dashboard, DASHBOARD_URL};
use std::fs;
use std::io::Write;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

// Source repository the bootstrap pulls from. The bundle pins the checkout to
// the commit captured at build time.
const REPO: &str = "Daybreak-AI-Labs/LightworkOS";
const GIT_REF: &str = env!("MAVERICK_INSTALL_REF");
#[cfg(windows)]
const INSTALL_SCRIPT_SHA256: &str = env!("MAVERICK_INSTALL_PS1_SHA256");
#[cfg(not(windows))]
const INSTALL_SCRIPT_SHA256: &str = env!("MAVERICK_INSTALL_SH_SHA256");
const CANCEL_GRACE: Duration = Duration::from_secs(3);
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LOG_LINE_BYTES: usize = 16 * 1024;
const MAX_LOG_EVENTS_PER_STREAM: usize = 10_000;
const CLEANUP_UNCERTAIN_PREFIX: &str = "Process-tree cleanup could not be verified: ";

#[cfg(windows)]
const INSTALL_SCRIPT: &str = include_str!(concat!(env!("OUT_DIR"), "/install.ps1"));
#[cfg(not(windows))]
const INSTALL_SCRIPT: &str = include_str!(concat!(env!("OUT_DIR"), "/install.sh"));

/// One install at a time, with cancellation remaining active until the owned
/// process tree has actually exited. Keeping the sender in state prevents a
/// close request or second invocation from mistaking "cancel requested" for
/// "cleanup complete."
struct InstallState {
    inventory_busy: std::sync::atomic::AtomicBool,
    control: Mutex<InstallControl>,
}

enum InstallControl {
    Idle,
    Running(watch::Sender<bool>),
    CleanupFailed,
}

impl Default for InstallState {
    fn default() -> Self {
        Self {
            inventory_busy: std::sync::atomic::AtomicBool::new(false),
            control: Mutex::new(InstallControl::Idle),
        }
    }
}

#[derive(serde::Serialize)]
struct InstallCommandError {
    code: &'static str,
    message: String,
}

impl InstallState {
    fn begin(&self) -> Result<watch::Receiver<bool>, String> {
        if self
            .inventory_busy
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("Wait for dependency inventory to finish.".into());
        }
        let mut control = self
            .control
            .lock()
            .map_err(|_| "Installer state lock is poisoned.".to_string())?;
        if self
            .inventory_busy
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("Wait for dependency inventory to finish.".into());
        }
        match &*control {
            InstallControl::Running(_) => {
                return Err("An installation is already running.".to_string())
            }
            InstallControl::CleanupFailed => {
                return Err(
                    "A previous installer process tree could not be verified as stopped; "
                        .to_string()
                        + "restart is blocked until the application exits.",
                )
            }
            InstallControl::Idle => {}
        }
        let (sender, receiver) = watch::channel(false);
        *control = InstallControl::Running(sender);
        Ok(receiver)
    }

    fn request_cancel(&self) -> Result<bool, String> {
        let control = self
            .control
            .lock()
            .map_err(|_| "Installer state lock is poisoned.".to_string())?;
        match &*control {
            InstallControl::Running(sender) => {
                sender.send_replace(true);
                Ok(true)
            }
            InstallControl::Idle => Ok(false),
            InstallControl::CleanupFailed => Err(
                "Process-tree cleanup is uncertain; cancellation cannot be reported as complete."
                    .to_string(),
            ),
        }
    }

    fn finish(&self, cleanup_verified: bool) {
        if let Ok(mut control) = self.control.lock() {
            *control = if cleanup_verified {
                InstallControl::Idle
            } else {
                InstallControl::CleanupFailed
            };
        }
    }

    fn is_active(&self) -> bool {
        // Poisoning is treated as active so a close cannot fail open while
        // ownership state is uncertain.
        self.control
            .lock()
            .map_or(true, |control| !matches!(&*control, InstallControl::Idle))
    }

    fn cleanup_failed(&self) -> bool {
        self.control.lock().map_or(true, |control| {
            matches!(&*control, InstallControl::CleanupFailed)
        })
    }
}

/// Synchronous ownership guard for the bootstrap and every child it creates.
///
/// Tokio's `kill_on_drop` covers the shell itself. This guard additionally
/// owns its process group on Unix and a KILL_ON_JOB_CLOSE Job Object on
/// Windows, so cancellation and application shutdown reap package-manager
/// descendants too.
struct ProcessTreeGuard {
    pid: u32,
    armed: bool,
    #[cfg(windows)]
    job: usize,
}

impl ProcessTreeGuard {
    #[cfg(unix)]
    fn attach(pid: u32) -> Result<Self, String> {
        if pid > i32::MAX as u32 {
            return Err(format!(
                "Installer process id {pid} cannot form a process group."
            ));
        }
        Ok(Self { pid, armed: true })
    }

    #[cfg(windows)]
    fn attach(pid: u32) -> Result<Self, String> {
        use std::mem::{size_of, zeroed};
        use std::ptr;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };

        // SAFETY: all handles are checked before use, the information buffer
        // has the exact documented type/size, and every failure path closes
        // each handle it acquired.
        unsafe {
            let job = CreateJobObjectW(ptr::null(), ptr::null());
            if job.is_null() {
                return Err(format!(
                    "Could not create installer process ownership job: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                let error = std::io::Error::last_os_error();
                CloseHandle(job);
                return Err(format!(
                    "Could not configure installer process ownership job: {error}"
                ));
            }

            let process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if process.is_null() {
                let error = std::io::Error::last_os_error();
                CloseHandle(job);
                return Err(format!(
                    "Could not open installer process for ownership: {error}"
                ));
            }
            let assigned = AssignProcessToJobObject(job, process);
            let assign_error = std::io::Error::last_os_error();
            CloseHandle(process);
            if assigned == 0 {
                CloseHandle(job);
                return Err(format!(
                    "Could not assign installer process tree to its ownership job: {assign_error}"
                ));
            }
            let mut guard = Self {
                pid,
                armed: true,
                job: job as usize,
            };
            if let Err(error) = Self::resume_suspended_windows_process(pid) {
                let _ = guard.terminate_hard();
                guard.disarm();
                return Err(error);
            }
            Ok(guard)
        }
    }

    #[cfg(windows)]
    fn resume_suspended_windows_process(pid: u32) -> Result<(), String> {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };

        // The process was created suspended, so it cannot create descendants
        // before Job assignment. Enumerate its sole initial thread only after
        // assignment, then resume it.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "Could not inspect suspended installer thread: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            let mut present = Thread32First(snapshot, &mut entry) != 0;
            while present {
                if entry.th32OwnerProcessID == pid {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if thread.is_null() {
                        let error = std::io::Error::last_os_error();
                        CloseHandle(snapshot);
                        return Err(format!(
                            "Could not open suspended installer thread: {error}"
                        ));
                    }
                    let previous_count = ResumeThread(thread);
                    let resume_error = std::io::Error::last_os_error();
                    CloseHandle(thread);
                    CloseHandle(snapshot);
                    if previous_count != 1 {
                        return Err(format!(
                            "Could not prove the owned installer started from exactly one suspension (previous count {previous_count}): {resume_error}"
                        ));
                    }
                    return Ok(());
                }
                present = Thread32Next(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
            Err(format!(
                "Could not find the suspended installer thread for process {pid}."
            ))
        }
    }

    #[cfg(unix)]
    fn terminate_soft(&self) -> Result<(), String> {
        self.signal_unix(libc::SIGTERM)
    }

    #[cfg(windows)]
    fn terminate_soft(&self) -> Result<(), String> {
        self.terminate_windows()
    }

    #[cfg(unix)]
    fn terminate_hard(&self) -> Result<(), String> {
        self.signal_unix(libc::SIGKILL)
    }

    #[cfg(windows)]
    fn terminate_hard(&self) -> Result<(), String> {
        self.terminate_windows()
    }

    #[cfg(unix)]
    fn signal_unix(&self, signal: i32) -> Result<(), String> {
        // SAFETY: the negative PID targets only the process group created for
        // this child before spawn. ESRCH means it already exited.
        let result = unsafe { libc::kill(-(self.pid as i32), signal) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!(
                "Could not signal installer process group {}: {error}",
                self.pid
            ))
        }
    }

    #[cfg(unix)]
    fn has_live_members(&self) -> Result<bool, String> {
        // Signal 0 probes the dedicated group without changing it.
        let result = unsafe { libc::kill(-(self.pid as i32), 0) };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(format!(
                "Could not verify installer process group {}: {error}",
                self.pid
            )),
        }
    }

    #[cfg(windows)]
    fn terminate_windows(&self) -> Result<(), String> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: `job` is an owned live handle while the guard is armed.
        if unsafe { TerminateJobObject(self.job as *mut _, 1) } != 0 {
            Ok(())
        } else {
            Err(format!(
                "Could not terminate installer process ownership job: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(windows)]
    fn active_processes(&self) -> Result<u32, String> {
        use std::mem::{size_of, zeroed};
        use std::ptr;
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        // SAFETY: `job` is a live owned handle and the output buffer matches
        // the requested information class exactly.
        let ok = unsafe {
            QueryInformationJobObject(
                self.job as *mut _,
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut _,
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(format!(
                "Could not inspect installer process ownership job: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(info.ActiveProcesses)
        }
    }

    fn disarm(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            // SAFETY: this guard owns the handle and closes it exactly once.
            unsafe {
                CloseHandle(self.job as *mut _);
            }
            self.job = 0;
        }
        self.armed = false;
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.terminate_hard();
        self.disarm();
    }
}

#[cfg(unix)]
async fn wait_for_empty_process_group(
    process_tree: &ProcessTreeGuard,
    timeout: Duration,
) -> Result<bool, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if !process_tree.has_live_members()? {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(windows)]
async fn wait_for_empty_job(
    process_tree: &ProcessTreeGuard,
    timeout: Duration,
) -> Result<bool, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if process_tree.active_processes()? == 0 {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[derive(Debug)]
enum ProcessTreeFinalizeError {
    VerifiedResidual(String),
    Uncertain(String),
}

async fn finalize_process_tree(
    process_tree: &mut ProcessTreeGuard,
    residual_is_error: bool,
) -> Result<(), ProcessTreeFinalizeError> {
    #[cfg(unix)]
    {
        let had_residual = process_tree
            .has_live_members()
            .map_err(ProcessTreeFinalizeError::Uncertain)?;
        if had_residual {
            process_tree
                .terminate_soft()
                .map_err(ProcessTreeFinalizeError::Uncertain)?;
            if !wait_for_empty_process_group(process_tree, CANCEL_GRACE)
                .await
                .map_err(ProcessTreeFinalizeError::Uncertain)?
            {
                process_tree
                    .terminate_hard()
                    .map_err(ProcessTreeFinalizeError::Uncertain)?;
                if !wait_for_empty_process_group(process_tree, CANCEL_GRACE)
                    .await
                    .map_err(ProcessTreeFinalizeError::Uncertain)?
                {
                    return Err(ProcessTreeFinalizeError::Uncertain(
                        "Installer process group still has live descendants after forced teardown."
                            .to_string(),
                    ));
                }
            }
        }
        process_tree.disarm();
        if had_residual && residual_is_error {
            return Err(ProcessTreeFinalizeError::VerifiedResidual(
                "Installer bootstrap exited while background descendants were still running; "
                    .to_string()
                    + "the owned process group was terminated.",
            ));
        }
        return Ok(());
    }

    #[cfg(windows)]
    {
        let had_residual = process_tree
            .active_processes()
            .map_err(ProcessTreeFinalizeError::Uncertain)?
            > 0;
        if had_residual {
            process_tree
                .terminate_hard()
                .map_err(ProcessTreeFinalizeError::Uncertain)?;
            if !wait_for_empty_job(process_tree, CANCEL_GRACE)
                .await
                .map_err(ProcessTreeFinalizeError::Uncertain)?
            {
                return Err(ProcessTreeFinalizeError::Uncertain(
                    "Installer ownership job still has live descendants after forced teardown."
                        .to_string(),
                ));
            }
        }
        process_tree.disarm();
        if had_residual && residual_is_error {
            Err(ProcessTreeFinalizeError::VerifiedResidual(
                "Installer bootstrap exited while background descendants were still running; "
                    .to_string()
                    + "the owned Windows Job was terminated.",
            ))
        } else {
            Ok(())
        }
    }
}

async fn verify_process_tree(
    process_tree: &mut ProcessTreeGuard,
    residual_is_error: bool,
) -> Result<(), String> {
    finalize_process_tree(process_tree, residual_is_error)
        .await
        .map_err(|error| match error {
            ProcessTreeFinalizeError::VerifiedResidual(message) => message,
            ProcessTreeFinalizeError::Uncertain(message) => {
                format!("{CLEANUP_UNCERTAIN_PREFIX}{message}")
            }
        })
}

/// Build the platform bootstrap command. Runs in headless mode
/// (`MAVERICK_NO_WIZARD`) so the install completes without the
/// interactive wizard, which a GUI can't drive over a pipe.
struct BootstrapCommand {
    command: Command,
    _script_dir: TempDir,
}

fn configure_process_tree(command: &mut Command) {
    command.kill_on_drop(true);
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        command.creation_flags(CREATE_SUSPENDED);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
}

fn stage_install_script() -> Result<(TempDir, std::path::PathBuf), String> {
    let extension = if cfg!(windows) { "ps1" } else { "sh" };
    let script_dir = tempfile::Builder::new()
        .prefix("maverick-install-")
        .tempdir()
        .map_err(|e| format!("Could not create a private installer staging directory: {e}"))?;
    let script_path = script_dir.path().join(format!("install.{extension}"));
    let mut script = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&script_path)
        .map_err(|e| format!("Could not create the staged installer script: {e}"))?;
    script
        .write_all(INSTALL_SCRIPT.as_bytes())
        .and_then(|_| script.sync_all())
        .map_err(|e| format!("Could not write the bundled installer script: {e}"))?;
    Ok((script_dir, script_path))
}

fn bootstrap_command() -> Result<BootstrapCommand, String> {
    let (script_dir, script_path) = stage_install_script()?;

    #[cfg(windows)]
    {
        let mut command = Command::new("powershell");
        command.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
        command.arg(&script_path);
        command
            .env("MAVERICK_NO_WIZARD", "1")
            .env("MAVERICK_REPO", REPO)
            .env("MAVERICK_REF", GIT_REF);
        configure_process_tree(&mut command);
        Ok(BootstrapCommand {
            command,
            _script_dir: script_dir,
        })
    }
    #[cfg(not(windows))]
    {
        let mut command = Command::new("bash");
        command.arg(&script_path);
        command
            .env("MAVERICK_NO_WIZARD", "1")
            .env("MAVERICK_REPO", REPO)
            .env("MAVERICK_REF", GIT_REF);
        configure_process_tree(&mut command);
        Ok(BootstrapCommand {
            command,
            _script_dir: script_dir,
        })
    }
}

async fn forward_output<R>(app: AppHandle, stream: &'static str, input: R)
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(input);
    let mut line = Vec::with_capacity(MAX_LOG_LINE_BYTES.min(4096));
    let mut truncated = false;
    let mut reported_emit_error = false;
    let mut emitted = 0_usize;
    let mut suppression_reported = false;
    let mut journal_error_reported = false;

    loop {
        let available = match reader.fill_buf().await {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = app.emit("install-log", format!("[{stream} read error: {error}]"));
                break;
            }
        };
        if available.is_empty() {
            if !line.is_empty() || truncated {
                let mut text = String::from_utf8_lossy(&line).into_owned();
                if truncated {
                    text.push_str(" … [line truncated]");
                }
                if emitted < MAX_LOG_EVENTS_PER_STREAM {
                    let _ = app.emit("install-log", text);
                }
            }
            break;
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let content_len = newline.unwrap_or(available.len());
        let remaining = MAX_LOG_LINE_BYTES.saturating_sub(line.len());
        let copy_len = content_len.min(remaining);
        line.extend_from_slice(&available[..copy_len]);
        if copy_len < content_len {
            truncated = true;
        }
        let consumed = newline.map_or(available.len(), |index| index + 1);
        reader.consume(consumed);

        if newline.is_some() {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let mut text = String::from_utf8_lossy(&line).into_owned();
            if truncated {
                text.push_str(" … [line truncated]");
            }
            if let Err(error) = bootstrap_recovery::progress(&app, &text) {
                if !journal_error_reported {
                    let _ = app.emit(
                        "install-log",
                        format!("[Recovery progress could not be saved: {error}]"),
                    );
                    journal_error_reported = true;
                }
            }
            if emitted < MAX_LOG_EVENTS_PER_STREAM {
                emitted += 1;
                if let Err(error) = app.emit("install-log", text) {
                    if !reported_emit_error {
                        eprintln!("Could not deliver installer {stream} progress: {error}");
                        reported_emit_error = true;
                    }
                }
            } else if !suppression_reported {
                let _ = app.emit(
                    "install-log",
                    format!(
                        "[{stream} log event limit reached; further output is being discarded]"
                    ),
                );
                suppression_reported = true;
            }
            line.clear();
            truncated = false;
        }
    }
}

/// Run the bootstrap, streaming stdout+stderr to the UI as best-effort
/// `install-log` events. The command response, not an event, is the
/// authoritative terminal result so event loss cannot strand the UI.
async fn run_bootstrap(app: AppHandle, mut cancel: watch::Receiver<bool>) -> Result<(), String> {
    let _ = app.emit(
        "install-log",
        format!(
            "Verified bootstrap source: {REPO}@{GIT_REF} (script sha256: {INSTALL_SCRIPT_SHA256})"
        ),
    );
    let mut bootstrap = bootstrap_command()?;
    bootstrap
        .command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = bootstrap
        .command
        .spawn()
        .map_err(|e| format!("Could not start the installer: {e}"))?;
    let pid = child
        .id()
        .ok_or_else(|| "Installer process started without a process id.".to_string())?;
    let mut process_tree = ProcessTreeGuard::attach(pid)?;

    let stdout = child.stdout.take().ok_or("no stdout handle")?;
    let stderr = child.stderr.take().ok_or("no stderr handle")?;

    // The scripts log progress to stderr and results to stdout; surface
    // both as one event stream so the user sees everything.
    let a = app.clone();
    let mut out = tokio::spawn(forward_output(a, "stdout", stdout));
    let mut err = tokio::spawn(forward_output(app.clone(), "stderr", stderr));

    let wait_for_cancel = async {
        loop {
            if *cancel.borrow() {
                break;
            }
            if cancel.changed().await.is_err() {
                // The state sender lives until `install` finishes. Losing it
                // unexpectedly is ownership uncertainty, so cancel.
                break;
            }
        }
    };

    let status = tokio::select! {
        result = child.wait() => Some(result),
        _ = wait_for_cancel => None,
    };

    if let Some(Err(error)) = &status {
        out.abort();
        err.abort();
        let _ = (&mut out).await;
        let _ = (&mut err).await;
        let signal_error = process_tree.terminate_hard().err();
        let _ = tokio::time::timeout(CANCEL_GRACE, child.wait()).await;
        if let Err(cleanup_error) = verify_process_tree(&mut process_tree, false).await {
            return Err(format!(
                "{cleanup_error} Installer wait also failed: {error}."
            ));
        }
        return Err(format!(
            "Could not wait for the installer: {error}.{}",
            signal_error
                .map(|value| format!(" Forced teardown failed: {value}."))
                .unwrap_or_default(),
        ));
    }
    let status = status.map(|result| result.expect("wait error handled above"));

    if status.is_none() {
        let soft_error = process_tree.terminate_soft().err();
        let mut wait_error = None;
        let exited = match tokio::time::timeout(CANCEL_GRACE, child.wait()).await {
            Ok(Ok(_)) => true,
            Ok(Err(error)) => {
                wait_error = Some(error.to_string());
                false
            }
            Err(_) => false,
        };
        let mut hard_error = None;
        if !exited {
            hard_error = process_tree.terminate_hard().err();
            match tokio::time::timeout(CANCEL_GRACE, child.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => wait_error = Some(error.to_string()),
                Err(_) => {
                    wait_error =
                        Some("installer leader did not exit after forced cancellation".to_string())
                }
            }
        }

        let drained = tokio::time::timeout(OUTPUT_DRAIN_TIMEOUT, async {
            let _ = (&mut out).await;
            let _ = (&mut err).await;
        })
        .await
        .is_ok();
        if !drained {
            out.abort();
            err.abort();
            let _ = (&mut out).await;
            let _ = (&mut err).await;
        }
        verify_process_tree(&mut process_tree, false).await?;
        if let Some(error) = wait_error {
            return Err(format!(
                "Installer cancellation reached a process wait error after verified tree teardown: {error}"
            ));
        }

        let detail = [
            soft_error.map(|error| format!(" Initial graceful tree signal failed: {error}")),
            hard_error.map(|error| format!(" Initial forced tree signal failed: {error}")),
        ]
        .into_iter()
        .flatten()
        .collect::<String>();
        return Err(format!(
            "Installation cancelled; the owned bootstrap process tree was terminated.{detail}"
        ));
    }

    let drained = tokio::time::timeout(OUTPUT_DRAIN_TIMEOUT, async {
        let _ = (&mut out).await;
        let _ = (&mut err).await;
    })
    .await
    .is_ok();
    if !drained {
        out.abort();
        err.abort();
        let _ = (&mut out).await;
        let _ = (&mut err).await;
        let signal_error = process_tree.terminate_hard().err();
        let _ = tokio::time::timeout(CANCEL_GRACE, child.wait()).await;
        verify_process_tree(&mut process_tree, false).await?;
        return Err(format!(
            concat!(
                "Installer exited but descendants kept its output pipes open; ",
                "the owned process tree was terminated.{}"
            ),
            signal_error
                .map(|error| format!(" Initial forced signal failed: {error}"))
                .unwrap_or_default()
        ));
    }
    verify_process_tree(&mut process_tree, true).await?;

    let status = status.expect("status checked above");
    if status.success() {
        Ok(())
    } else {
        let msg = format!(
            "The installer exited with an error (code {:?}).",
            status.code()
        );
        Err(msg)
    }
}

#[tauri::command]
async fn install(
    app: AppHandle,
    state: State<'_, InstallState>,
    review: String,
    confirm_dependencies_reviewed: bool,
) -> Result<(), InstallCommandError> {
    let cancel = state.begin().map_err(|message| InstallCommandError {
        code: "failed",
        message,
    })?;
    if let Err(message) = bootstrap_recovery::begin(&app, &review, confirm_dependencies_reviewed) {
        state.finish(true);
        return Err(InstallCommandError {
            code: "preflight_required",
            message,
        });
    }
    let result = run_bootstrap(app.clone(), cancel).await;
    let cleanup_verified = !matches!(
        &result,
        Err(message) if message.starts_with(CLEANUP_UNCERTAIN_PREFIX)
    );
    state.finish(cleanup_verified);
    let outcome = if result.is_ok() {
        "completed"
    } else if !cleanup_verified {
        "cleanup_uncertain"
    } else if matches!(&result, Err(message) if message.starts_with("Installation cancelled;")) {
        "cancelled"
    } else {
        "failed"
    };
    if let Err(message) = bootstrap_recovery::mark(&app, outcome) {
        return Err(InstallCommandError { code: "inventory_unknown", message: format!("Installation result: {outcome}. Its durable recovery receipt could not be saved: {message}. Recheck installed dependencies before retrying.") });
    }
    result.map_err(|message| InstallCommandError {
        code: if message.starts_with("Installation cancelled;") {
            "cancelled"
        } else if message.starts_with(CLEANUP_UNCERTAIN_PREFIX) {
            "cleanup_failed"
        } else {
            "failed"
        },
        message,
    })
}

struct InventoryBusy<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for InventoryBusy<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[tauri::command]
async fn bootstrap_inventory(
    app: AppHandle,
    state: State<'_, InstallState>,
) -> Result<bootstrap_recovery::Journal, String> {
    state
        .inventory_busy
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .map_err(|_| "A dependency check is already running.")?;
    let _busy = InventoryBusy(&state.inventory_busy);
    if state.is_active() {
        return Err(
            "Finish the owned installation and cleanup before checking dependencies.".into(),
        );
    }
    bootstrap_recovery::inventory(&app).await
}

#[tauri::command]
fn open_dependency_repair(state: State<'_, InstallState>) -> Result<(), String> {
    if state.is_active()
        || state
            .inventory_busy
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err("Finish the current local check or installer before opening OS repair.".into());
    }
    #[cfg(windows)]
    let mut command = {
        let root =
            std::env::var_os("SystemRoot").ok_or("Windows system directory is unavailable.")?;
        let mut cmd =
            std::process::Command::new(std::path::PathBuf::from(root).join("explorer.exe"));
        cmd.arg("ms-settings:appsfeatures");
        cmd
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut cmd = std::process::Command::new("/usr/bin/open");
        cmd.args(["-a", "System Settings"]);
        cmd
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut cmd = std::process::Command::new("gnome-software");
        cmd.args(["--mode", "installed"]);
        cmd
    };
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_| "Could not open this platform's app manager. Open the OS application settings, review Git/Python/pipx, then select Recheck dependencies here.")?;
    Ok(())
}

#[tauri::command]
fn cancel_install(state: State<'_, InstallState>) -> Result<(), String> {
    // A completion racing the user's click is already safe and needs no error.
    state.request_cancel().map(|_| ())
}

#[tauri::command]
fn force_exit_after_cleanup_failure(
    app: AppHandle,
    state: State<'_, InstallState>,
) -> Result<(), String> {
    if !state.cleanup_failed() {
        return Err("There is no unresolved installer cleanup failure.".to_string());
    }
    app.exit(2);
    Ok(())
}

#[tauri::command]
fn dashboard_diagnostics(state: State<'_, Dashboard>) -> Result<String, String> {
    state.diagnostics()
}

#[tauri::command]
async fn open_lightwork(
    app: AppHandle,
    install_state: State<'_, InstallState>,
    dashboard: State<'_, Dashboard>,
) -> Result<(), String> {
    if install_state.is_active() {
        return Err("Finish installation and cleanup before opening Lightwork.".into());
    }
    dashboard.start()?;
    // Give the Python app time to start. An unconfigured installation still
    // serves its onboarding page; no terminal wizard is needed here.
    for _ in 0..30 {
        let readiness =
            tauri::async_runtime::spawn_blocking(lightwork_desktop_runtime::dashboard_readiness)
                .await
                .map_err(|e| e.to_string())?;
        if matches!(readiness, lightwork_desktop_runtime::Readiness::Conflict) {
            return Err("Another service occupies the dashboard address. Close that service or contact your administrator; it was not adopted.".into());
        }
        if matches!(
            readiness,
            lightwork_desktop_runtime::Readiness::Ready
                | lightwork_desktop_runtime::Readiness::SetupRequired
        ) {
            if let Some(window) = app.get_webview_window("dashboard") {
                window.show().map_err(|error| error.to_string())?;
                return window.set_focus().map_err(|error| error.to_string());
            }
            tauri::WebviewWindowBuilder::new(
                &app,
                "dashboard",
                tauri::WebviewUrl::External(
                    DASHBOARD_URL
                        .parse()
                        .map_err(|_| "Invalid dashboard address.")?,
                ),
            )
            .title("Lightwork")
            .inner_size(1280.0, 860.0)
            .min_inner_size(640.0, 480.0)
            .build()
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err("Lightwork has not opened yet. Review startup details, then try again.".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(InstallState::default())
        .manage(Dashboard::default())
        .invoke_handler(tauri::generate_handler![
            install,
            bootstrap_inventory,
            open_dependency_repair,
            cancel_install,
            force_exit_after_cleanup_failure,
            open_lightwork,
            dashboard_diagnostics
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<InstallState>();
                if state.is_active() {
                    api.prevent_close();
                    let event = if state.cleanup_failed() {
                        "install-cleanup-failed-close-requested"
                    } else {
                        "install-close-requested"
                    };
                    let _ = window.emit(event, ());
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("tauri runtime error")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                app.state::<Dashboard>().stop_owned();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_running_tree() -> Command {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("powershell");
            command.args([
                "-NoProfile",
                "-Command",
                r#"$child = Start-Process -FilePath "$env:SystemRoot\System32\ping.exe" -ArgumentList "-t","127.0.0.1" -PassThru; Write-Output $child.Id; [Console]::Out.Flush(); Wait-Process -Id $child.Id"#,
            ]);
            command
        };
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 60 & child=$!; echo $child; wait"]);
            command
        };
        configure_process_tree(&mut command);
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        command
    }

    #[tokio::test]
    async fn cancellation_reaps_a_long_running_descendant_tree() {
        let mut command = long_running_tree();
        let mut child = command.spawn().expect("spawn test bootstrap");
        let pid = child.id().expect("test bootstrap pid");
        let mut process_tree = ProcessTreeGuard::attach(pid).expect("own process tree");
        let stdout = child.stdout.take().expect("test stdout");
        let mut lines = BufReader::new(stdout).lines();
        let descendant = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("descendant pid timeout")
            .expect("read descendant pid")
            .expect("descendant pid line");
        assert!(descendant.trim().parse::<u32>().is_ok());

        process_tree
            .terminate_soft()
            .expect("signal owned process tree");
        tokio::time::timeout(CANCEL_GRACE, child.wait())
            .await
            .expect("bootstrap cancellation timeout")
            .expect("reap bootstrap");
        finalize_process_tree(&mut process_tree, false)
            .await
            .expect("reap descendants");
    }
}
