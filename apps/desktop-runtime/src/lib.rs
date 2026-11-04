//! Fixed local dashboard launch and bounded, in-memory startup diagnostics.
//! Both desktop entry points use the same installation lookup and retry rules.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DASHBOARD_URL: &str = "http://127.0.0.1:8765/";
const MAX_LOG_BYTES: usize = 32 * 1024;
const OWNED_STOP_DEADLINE: Duration = Duration::from_secs(5);
const DESKTOP_DRAIN: &[u8] = b"LIGHTWORK_DESKTOP_DRAIN_V1\n";
/// Windows reports a refused loopback connection only after about two seconds
/// (2.1 to 2.2 s on hosted runners). A shorter connect budget read a free port
/// as `Unavailable`, so the shell refused to start its own dashboard.
const READINESS_CONNECT_TIMEOUT: Duration = Duration::from_millis(3000);

type Logs = Arc<Mutex<String>>;

#[derive(Default)]
struct Control {
    child: Option<Child>,
    logs: Logs,
    binary: Option<PathBuf>,
    child_environment: Vec<(OsString, OsString)>,
    recovery: bool,
    drain_timeout: Option<Duration>,
    // Counts stop requests so a start that probed before one never launches after it.
    stops: u64,
}

#[derive(Default)]
pub struct Dashboard(Mutex<Control>);

/// Allowlisted startup facts; deliberately excludes logs, paths and config.
#[derive(Debug, PartialEq, Eq)]
pub struct StartupSupport {
    pub packaged_runtime_available: Option<bool>,
    pub process_state: &'static str,
    pub recovery_mode: bool,
}

pub fn listening() -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8765));
    TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    SetupRequired,
    NotRunning,
    Conflict,
    Unavailable,
}

fn readiness_headers(headers: &[u8]) -> Readiness {
    let Ok(text) = std::str::from_utf8(headers) else {
        return Readiness::Conflict;
    };
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let status = first.split_whitespace().nth(1).unwrap_or_default();
    if !first.starts_with("HTTP/1.") {
        return Readiness::Conflict;
    }
    let identity: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-lightwork-service"))
        .map(|(_, value)| value.trim())
        .collect();
    if identity != ["dashboard-v1"] {
        return Readiness::Conflict;
    }
    match status {
        "200" => Readiness::Ready,
        "503" => Readiness::SetupRequired,
        _ => Readiness::Unavailable,
    }
}

fn probe_address(address: SocketAddr) -> Readiness {
    probe_with(|| TcpStream::connect_timeout(&address, READINESS_CONNECT_TIMEOUT))
}

fn probe_with(connect: impl FnOnce() -> std::io::Result<TcpStream>) -> Readiness {
    let mut stream = match connect() {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Readiness::NotRunning
        }
        Err(_) => return Readiness::Unavailable,
    };
    // The headers get their own budget from the moment the connection exists:
    // a connect Windows completes late must not leave none for them.
    let started = Instant::now();
    let timeout = Some(Duration::from_millis(200));
    if stream.set_read_timeout(timeout).is_err() || stream.set_write_timeout(timeout).is_err() {
        return Readiness::Unavailable;
    }
    if stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n").is_err() {
        return Readiness::Unavailable;
    }
    let mut headers = Vec::new();
    let mut chunk = [0u8; 512];
    while started.elapsed() < Duration::from_millis(2000) && headers.len() <= 8192 {
        match stream.read(&mut chunk) {
            Ok(0) => return Readiness::Conflict,
            Ok(count) => {
                headers.extend_from_slice(&chunk[..count]);
                if let Some(end) = headers.windows(4).position(|part| part == b"\r\n\r\n") {
                    return readiness_headers(&headers[..end]);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                ()
            }
            Err(_) => return Readiness::Unavailable,
        }
    }
    Readiness::Unavailable
}

/// Fixed loopback identity handshake, bounded independently of the webview.
pub fn dashboard_readiness() -> Readiness {
    probe_address(SocketAddr::from(([127, 0, 0, 1], 8765)))
}

fn wait_for_listener_exit(mut is_listening: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !is_listening() {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn record(logs: &Logs, text: &str) {
    if let Ok(mut log) = logs.lock() {
        log.push_str(text);
        if log.len() > MAX_LOG_BYTES {
            let mut start = log.len() - MAX_LOG_BYTES;
            while !log.is_char_boundary(start) {
                start += 1;
            }
            log.drain(..start);
        }
    }
}

fn capture(mut stream: impl Read + Send + 'static, logs: Logs) {
    std::thread::spawn(move || {
        let mut bytes = [0u8; 2048];
        loop {
            match stream.read(&mut bytes) {
                Ok(0) => break,
                Ok(size) => record(&logs, &String::from_utf8_lossy(&bytes[..size])),
                Err(error) => {
                    record(
                        &logs,
                        &format!("\nCould not read startup output: {error}\n"),
                    );
                    break;
                }
            }
        }
    });
}

/// Check installer locations explicitly because GUI apps may have an old PATH.
fn maverick_bin() -> OsString {
    let exe = if cfg!(windows) {
        "maverick.exe"
    } else {
        "maverick"
    };
    if let Some(explicit) = std::env::var_os("MAVERICK_BIN") {
        return explicit;
    }
    let mut candidates = Vec::<PathBuf>::new();
    if let Some(dir) = std::env::var_os("PIPX_BIN_DIR") {
        candidates.push(PathBuf::from(dir).join(exe));
    }
    for var in ["HOME", "USERPROFILE"] {
        if let Some(home) = std::env::var_os(var) {
            let home = PathBuf::from(home);
            candidates.push(home.join(".local").join("bin").join(exe));
            candidates.push(home.join("bin").join(exe));
        }
    }
    for dir in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        candidates.push(Path::new(dir).join(exe));
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(PathBuf::into_os_string)
        .unwrap_or_else(|| exe.into())
}

fn spawn_dashboard(
    logs: &Logs,
    binary: Option<&Path>,
    recovery: bool,
    child_environment: &[(OsString, OsString)],
) -> Result<Child, String> {
    let drain_timeout = configured_drain_timeout(child_environment)?;
    let mut command = Command::new(
        binary
            .map(|path| path.as_os_str().to_owned())
            .unwrap_or_else(maverick_bin),
    );
    command
        .args(["dashboard", "--host", "127.0.0.1", "--port", "8765"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.envs(child_environment.iter().cloned());
    command.env("MAVERICK_DESKTOP_CONTROL", "stdin-v1");
    // Native and Python shutdown share this exact budget, including an
    // explicitly configured legacy timeout. No extra independent drain wait.
    command.env(
        "MAVERICK_SHUTDOWN_TIMEOUT",
        drain_timeout.as_secs_f64().to_string(),
    );
    if recovery {
        command.arg("--recovery-mode");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().map_err(|error| {
        let message = format!("Lightwork could not start: {error}");
        record(logs, &format!("{message}\n"));
        message
    })?;
    if let Some(stdout) = child.stdout.take() {
        capture(stdout, Arc::clone(logs));
    }
    if let Some(stderr) = child.stderr.take() {
        capture(stderr, Arc::clone(logs));
    }
    Ok(child)
}

fn configured_drain_timeout(environment: &[(OsString, OsString)]) -> Result<Duration, String> {
    let value = |name: &str| {
        environment
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .or_else(|| std::env::var_os(name))
    };
    let raw = value("MAVERICK_SHUTDOWN_TIMEOUT")
        .or_else(|| value("MAVERICK_DRAIN_TIMEOUT"))
        .unwrap_or_else(|| "20".into());
    let seconds = raw
        .to_str()
        .and_then(|text| text.trim().parse::<f64>().ok())
        .filter(|seconds| seconds.is_finite() && (0.0..=300.0).contains(seconds))
        .ok_or("Dashboard shutdown timeout must be finite and between 0 and 300 seconds.")?;
    Ok(Duration::from_secs_f64(seconds))
}

fn reap(control: &mut Control) -> Result<(), String> {
    if let Some(child) = control.child.as_mut() {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            record(&control.logs, &format!("\nLightwork exited: {status}\n"));
            control.child = None;
        }
    }
    Ok(())
}

fn ensure_started(
    control: &mut Control,
    is_listening: impl FnOnce() -> bool,
    spawn: impl FnOnce(&Logs) -> Result<Child, String>,
) -> Result<String, String> {
    reap(control)?;
    if is_listening() {
        return Ok("Lightwork is responding on this computer.".into());
    }
    if control.child.is_some() {
        return Ok("Lightwork is still starting.".into());
    }
    // Old output readers retain the old buffer, so a retry cannot mix attempts.
    control.logs = Logs::default();
    record(&control.logs, "Starting Lightwork on this computer.\n");
    control.child = Some(spawn(&control.logs)?);
    Ok("Starting Lightwork…".into())
}

impl Dashboard {
    pub fn startup_support(&self) -> Result<StartupSupport, String> {
        let mut control = self.0.lock().map_err(|_| "Startup state is unavailable.")?;
        let process_state = match control.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(None) => "running",
                Ok(Some(_)) => "exited",
                Err(_) => "unavailable",
            },
            None => "not_started",
        };
        Ok(StartupSupport {
            packaged_runtime_available: control.binary.as_ref().map(|path| path.is_file()),
            process_state,
            recovery_mode: control.recovery,
        })
    }

    /// Customer packages pin their bundled runtime. A missing sidecar fails
    /// visibly rather than falling through to PATH or an environment override.
    pub fn with_binary(binary: PathBuf) -> Self {
        Self(Mutex::new(Control {
            binary: Some(binary),
            ..Control::default()
        }))
    }

    /// Configure a single child-only authority without adding it to the
    /// desktop process environment or unrelated children.
    pub fn with_environment(name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        Self(Mutex::new(Control {
            child_environment: vec![(name.into(), value.into())],
            ..Control::default()
        }))
    }

    pub fn with_binary_and_environment(
        binary: PathBuf,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Self {
        Self(Mutex::new(Control {
            binary: Some(binary),
            child_environment: vec![(name.into(), value.into())],
            ..Control::default()
        }))
    }

    pub fn start(&self) -> Result<String, String> {
        self.start_with(dashboard_readiness)
    }

    fn start_with(&self, probe: impl FnOnce() -> Readiness) -> Result<String, String> {
        let stops = self
            .0
            .lock()
            .map_err(|_| "Startup state is unavailable.")?
            .stops;
        // Windows takes about two seconds to refuse a free port. Probe without
        // the state lock so support reports and diagnostics stay answerable;
        // ensure_started still refuses a second owned child.
        let readiness = probe();
        let mut control = self.0.lock().map_err(|_| "Startup state is unavailable.")?;
        if control.stops != stops {
            // Quit, the updater's exit hook or maintenance stopped Lightwork
            // while this check ran; launching now would outlive that stop.
            return Err(
                "Lightwork was stopped during the startup check. Select Retry to start it again."
                    .into(),
            );
        }
        let binary = control.binary.clone();
        let child_environment = control.child_environment.clone();
        control.drain_timeout = Some(configured_drain_timeout(&child_environment)?);
        let recovery = control.recovery;
        let verified = match readiness {
            Readiness::Ready | Readiness::SetupRequired => true,
            Readiness::NotRunning => false,
            Readiness::Conflict => return Err("Port 8765 is occupied by an unrecognized service. No process was stopped. Close or reconfigure that service, then select Retry; use the support report if the conflict is unclear.".into()),
            Readiness::Unavailable => return Err("The local service did not complete the Lightwork identity check. No process was stopped. Select Retry or create a support report.".into()),
        };
        ensure_started(
            &mut control,
            || verified,
            |logs| spawn_dashboard(logs, binary.as_deref(), recovery, &child_environment),
        )
    }

    /// Restart only this app's owned process into a fixed local mode. A
    /// separately managed dashboard is never stopped or reported as isolated.
    pub fn switch_recovery_mode(&self, recovery: bool) -> Result<String, String> {
        let mut control = self.0.lock().map_err(|_| "Startup state is unavailable.")?;
        reap(&mut control)?;
        may_switch_mode(control.child.is_some(), listening())?;
        let deadline = stop_control(&mut control)?;
        // Windows can finish the owned bootloader's termination before its
        // worker's listening socket closes. Observe closure within a bound;
        // never start recovery while the previous workspace still responds.
        if !wait_for_listener_exit(
            listening,
            deadline.saturating_duration_since(Instant::now()),
        ) {
            return Err("The previous workspace is still responding. Recovery has not started; retry after it closes.".into());
        }
        control.recovery = recovery;
        let binary = control.binary.clone();
        let child_environment = control.child_environment.clone();
        control.drain_timeout = Some(configured_drain_timeout(&child_environment)?);
        ensure_started(
            &mut control,
            || false,
            |logs| spawn_dashboard(logs, binary.as_deref(), recovery, &child_environment),
        )
    }

    pub fn diagnostics(&self) -> Result<String, String> {
        let mut control = self.0.lock().map_err(|_| "Startup state is unavailable.")?;
        reap(&mut control)?;
        let log = control
            .logs
            .lock()
            .map_err(|_| "Startup details are unavailable.")?;
        Ok(if log.is_empty() {
            "No startup output was recorded. Lightwork may already be running independently.".into()
        } else {
            log.clone()
        })
    }

    /// An independently running dashboard is never placed in our owned state.
    pub fn stop_owned(&self) {
        if let Ok(mut control) = self.0.lock() {
            if let Err(error) = stop_control(&mut control) {
                record(&control.logs, &format!("\n{error}\n"));
            }
        }
    }

    /// Maintenance may pause only a process owned by this desktop instance.
    pub fn pause_for_maintenance(&self) -> Result<(), String> {
        self.pause_for_maintenance_with(listening)
    }

    fn pause_for_maintenance_with(
        &self,
        mut is_listening: impl FnMut() -> bool,
    ) -> Result<(), String> {
        let mut control = self.0.lock().map_err(|_| "Startup state is unavailable.")?;
        reap(&mut control)?;
        may_switch_mode(control.child.is_some(), is_listening())?;
        let deadline = stop_control(&mut control)?;
        if !wait_for_listener_exit(
            is_listening,
            deadline.saturating_duration_since(Instant::now()),
        ) {
            return Err("Lightwork is still responding. Installation has not started; retry after it closes.".into());
        }
        Ok(())
    }
}

fn may_switch_mode(owned: bool, responding: bool) -> Result<(), String> {
    if responding && !owned {
        return Err("This workspace is managed outside the desktop app. Its administrator must coordinate recovery; no process was stopped.".into());
    }
    Ok(())
}

fn wait_for_child_exit(child: &mut Child, deadline: Instant) -> Result<bool, String> {
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(true);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn stop_control(control: &mut Control) -> Result<Instant, String> {
    let grace = control.drain_timeout.unwrap_or(Duration::from_secs(20));
    stop_control_with_budget(control, grace, OWNED_STOP_DEADLINE)
}

fn stop_control_with_budget(
    control: &mut Control,
    grace: Duration,
    force: Duration,
) -> Result<Instant, String> {
    control.stops = control.stops.wrapping_add(1);
    let start = Instant::now();
    let mut deadline = start + grace + force;
    if let Some(child) = control.child.as_mut() {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            control.child = None;
            return Ok(deadline);
        }
        if let Some(mut channel) = child.stdin.take() {
            record(
                &control.logs,
                "\nSaving active work before closing Lightwork…\n",
            );
            if channel.write_all(DESKTOP_DRAIN).is_ok()
                && wait_for_child_exit(child, start + grace)?
            {
                record(&control.logs, "Lightwork completed graceful shutdown.\n");
                control.child = None;
                return Ok(deadline);
            }
        }
        record(
            &control.logs,
            "Graceful shutdown did not complete; stopping the owned process tree.\n",
        );
        deadline = deadline.min(Instant::now() + force);
        // A frozen one-file runtime owns an extraction/worker child.
        // Kill only this still-live owned process tree before MSI
        // replaces its files; killing just the bootloader leaves the
        // dashboard and its file locks behind on Windows.
        #[cfg(windows)]
        if matches!(child.try_wait(), Ok(None)) {
            use std::os::windows::process::CommandExt;
            if let Some(system_root) = std::env::var_os("SystemRoot") {
                let killer = Command::new(PathBuf::from(system_root).join("System32/taskkill.exe"))
                    .args(["/PID", &child.id().to_string(), "/T", "/F"])
                    .creation_flags(0x0800_0000)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
                if let Ok(mut killer) = killer {
                    if !wait_for_child_exit(&mut killer, deadline)? {
                        let _ = killer.kill();
                    }
                }
            }
        }
        #[cfg(unix)]
        if matches!(child.try_wait(), Ok(None)) {
            // Only children spawned into their own process group reach here.
            // Signal that owned group before reaping its leader.
            unsafe extern "C" {
                fn kill(pid: i32, signal: i32) -> i32;
            }
            unsafe {
                kill(-(child.id() as i32), 9);
            }
        }
        let _ = child.kill();
        if !wait_for_child_exit(child, deadline)? {
            // Retain the handle and refuse maintenance/recovery until its
            // actual exit can be observed. A timeout is never quiescence.
            return Err("The owned Lightwork process is still stopping. Maintenance and recovery have not started.".into());
        }
        control.child = None;
    }
    Ok(deadline)
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        self.stop_owned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_exact_dashboard_identity_even_for_successful_http() {
        for status in ["200", "404", "500"] {
            assert_eq!(
                readiness_headers(
                    format!("HTTP/1.1 {status} fixture\r\nServer: unrelated").as_bytes()
                ),
                Readiness::Conflict
            );
        }
        assert_eq!(
            readiness_headers(b"HTTP/1.1 200 OK\r\nX-Lightwork-Service: dashboard-v1"),
            Readiness::Ready
        );
        assert_eq!(
            readiness_headers(b"HTTP/1.1 503 Setup\r\nx-lightwork-service: dashboard-v1"),
            Readiness::SetupRequired
        );
        assert_eq!(readiness_headers(b"HTTP/1.1 200 OK\r\nx-lightwork-service: dashboard-v1\r\nX-Lightwork-Service: dashboard-v1"), Readiness::Conflict);
    }

    #[test]
    fn a_free_port_reads_as_not_running_even_where_refusal_is_slow() {
        use std::net::TcpListener;
        // Hosted Windows runners took 2.1 to 2.2 s to refuse a free loopback
        // port; anything shorter made the shell refuse to start its dashboard.
        assert!(READINESS_CONNECT_TIMEOUT >= Duration::from_millis(3000));
        for _ in 0..5 {
            let address = TcpListener::bind(("127.0.0.1", 0))
                .unwrap()
                .local_addr()
                .unwrap();
            let readiness = probe_address(address);
            if readiness == Readiness::NotRunning {
                return;
            }
            // A parallel test may have taken the released port. Only a port
            // that is still free and was not read as free is a failure.
            if TcpListener::bind(address).is_ok() {
                panic!("a free port read as {readiness:?}");
            }
        }
        panic!("no released loopback port stayed free long enough to probe");
    }

    #[test]
    fn a_connection_that_opens_late_still_gets_its_whole_header_budget() {
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 256];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).unwrap();
                if count == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nX-Lightwork-Service: dashboard-v1\r\n\r\n")
                .unwrap();
        });
        // Windows can complete a loopback connect after about two seconds of
        // SYN retries when the dashboard binds during them.
        let readiness = probe_with(|| {
            let stream = TcpStream::connect(address)?;
            std::thread::sleep(Duration::from_millis(2100));
            Ok(stream)
        });
        assert_eq!(readiness, Readiness::Ready);
        worker.join().unwrap();
    }

    #[test]
    fn stuck_native_identity_probe_has_an_overall_deadline() {
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
        });
        let began = Instant::now();
        assert_eq!(probe_address(address), Readiness::Unavailable);
        assert!(began.elapsed() < Duration::from_millis(2600));
        worker.join().unwrap();
    }

    #[test]
    fn owned_stop_wait_observes_actual_socket_closure_before_continuing() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let closed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&closed);
        let (trigger, started) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            let deadline = Instant::now() + Duration::from_millis(100);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => drop(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("synthetic listener failed: {error}"),
                }
            }
            drop(listener);
            observed.store(true, Ordering::SeqCst);
        });
        let mut trigger = Some(trigger);
        assert!(!closed.load(Ordering::SeqCst));
        assert!(wait_for_listener_exit(
            || {
                let responding =
                    TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok();
                if responding {
                    if let Some(trigger) = trigger.take() {
                        trigger.send(()).unwrap();
                    }
                }
                responding
            },
            Duration::from_secs(2),
        ));
        worker.join().unwrap();
        assert!(closed.load(Ordering::SeqCst));
    }

    #[test]
    fn owned_stop_wait_refuses_a_listener_that_outlives_the_deadline() {
        let began = Instant::now();
        let mut probes = 0;
        assert!(!wait_for_listener_exit(
            || {
                probes += 1;
                true
            },
            Duration::from_millis(60),
        ));
        assert!(probes >= 1);
        assert!(began.elapsed() >= Duration::from_millis(60));
    }

    #[test]
    fn owned_stop_wait_does_not_delay_an_already_closed_listener() {
        let mut probes = 0;
        assert!(wait_for_listener_exit(
            || {
                probes += 1;
                false
            },
            Duration::ZERO,
        ));
        assert_eq!(probes, 1);
    }

    #[test]
    fn startup_state_stays_answerable_while_the_readiness_probe_runs() {
        // On Windows the probe waits about two seconds for a refused connect.
        // Support reports and diagnostics must not wait behind it.
        let dashboard = std::sync::Arc::new(Dashboard::with_binary(
            std::env::temp_dir().join("lightwork-missing-probe-test-runtime.exe"),
        ));
        let (probing, probe_started) = std::sync::mpsc::channel();
        let starter = {
            let dashboard = dashboard.clone();
            std::thread::spawn(move || {
                dashboard.start_with(|| {
                    probing.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(1500));
                    Readiness::Conflict
                })
            })
        };
        probe_started.recv().unwrap();
        let began = Instant::now();
        assert_eq!(
            dashboard.startup_support().unwrap().process_state,
            "not_started"
        );
        dashboard.diagnostics().unwrap();
        assert!(began.elapsed() < Duration::from_millis(500));
        // A conflicting listener still refuses to start a second dashboard.
        assert!(starter.join().unwrap().is_err());
    }

    #[test]
    fn a_start_whose_readiness_check_outlived_a_stop_launches_nothing() {
        // Quitting, or the updater's exit hook, during the probe must not
        // leave a newly launched dashboard behind the closing app.
        let dashboard = Dashboard::with_binary(
            std::env::temp_dir().join("lightwork-missing-stop-race-test-runtime.exe"),
        );
        let result = dashboard.start_with(|| {
            dashboard.stop_owned();
            Readiness::NotRunning
        });
        assert_eq!(
            result.unwrap_err(),
            "Lightwork was stopped during the startup check. Select Retry to start it again."
        );
        assert!(!dashboard
            .diagnostics()
            .unwrap()
            .contains("Starting Lightwork"));
    }

    #[test]
    fn startup_support_excludes_private_logs_and_reports_pinned_runtime_state() {
        let dashboard = Dashboard::with_binary(
            std::env::temp_dir().join("lightwork-missing-startup-test-runtime.exe"),
        );
        {
            let mut control = dashboard.0.lock().unwrap();
            record(&control.logs, "private fixture token and customer path");
            control.recovery = true;
        }
        assert_eq!(
            dashboard.startup_support().unwrap(),
            StartupSupport {
                packaged_runtime_available: Some(false),
                process_state: "not_started",
                recovery_mode: true,
            }
        );
        assert_eq!(
            Dashboard::default()
                .startup_support()
                .unwrap()
                .packaged_runtime_available,
            None
        );
        assert!(!format!("{:?}", dashboard.startup_support().unwrap()).contains("private"));
    }

    #[test]
    fn recovery_cannot_stop_an_independently_managed_workspace() {
        assert!(may_switch_mode(false, true).is_err());
        assert!(may_switch_mode(false, false).is_ok());
        assert!(may_switch_mode(true, true).is_ok());
    }

    #[test]
    fn missing_customer_runtime_cannot_fall_back_to_an_installed_cli() {
        let missing = std::env::temp_dir().join("lightwork-no-such-customer-runtime.exe");
        let logs = Logs::default();
        assert!(spawn_dashboard(&logs, Some(&missing), false, &[]).is_err());
        assert!(logs.lock().unwrap().contains("could not start"));
    }

    #[test]
    fn customer_runtime_path_remains_pinned_across_retries() {
        let path = PathBuf::from("customer-runtime/maverick.exe");
        let dashboard = Dashboard::with_binary(path.clone());
        let mut control = dashboard.0.lock().unwrap();
        for _ in 0..2 {
            let _ = ensure_started(&mut control, || false, |_| Err("missing".into()));
            assert_eq!(control.binary.as_ref(), Some(&path));
        }
    }

    #[test]
    fn child_fixture() {
        let mode = std::env::var("LIGHTWORK_RUNTIME_TEST_CHILD").ok();
        if mode.as_deref() == Some("descendant") {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            std::fs::write(
                std::env::var_os("LIGHTWORK_RUNTIME_TEST_MARKER").unwrap(),
                format!("{}\n{}", std::process::id(), listener.local_addr().unwrap()),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => drop(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("owned descendant listener failed: {error}"),
                }
            }
        } else if mode.as_deref() == Some("tree") {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "tests::child_fixture"])
                .env("LIGHTWORK_RUNTIME_TEST_CHILD", "descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x0800_0000);
            }
            let mut descendant = command.spawn().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            let _ = descendant.kill();
            let _ = descendant.wait();
        } else if mode.as_deref() == Some("graceful") {
            use std::io::BufRead;
            let mut command = String::new();
            std::io::stdin().lock().read_line(&mut command).unwrap();
            assert_eq!(command.as_bytes(), DESKTOP_DRAIN);
            std::fs::write(
                std::env::var_os("LIGHTWORK_RUNTIME_TEST_MARKER").unwrap(),
                "final state saved",
            )
            .unwrap();
        } else if mode.is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    fn fixture_child(running: bool) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "tests::child_fixture"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if running {
            command.env("LIGHTWORK_RUNTIME_TEST_CHILD", "1");
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        command.spawn().unwrap()
    }

    #[test]
    fn graceful_owned_child_persists_final_state_before_exit() {
        let marker =
            std::env::temp_dir().join(format!("lightwork-drain-{}.txt", std::process::id()));
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "tests::child_fixture"])
            .env("LIGHTWORK_RUNTIME_TEST_CHILD", "graceful")
            .env("LIGHTWORK_RUNTIME_TEST_MARKER", &marker)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut control = Control {
            child: Some(command.spawn().unwrap()),
            ..Control::default()
        };
        stop_control_with_budget(&mut control, Duration::from_secs(3), Duration::from_secs(1))
            .unwrap();
        assert!(control.child.is_none());
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "final state saved"
        );
        assert!(control
            .logs
            .lock()
            .unwrap()
            .contains("completed graceful shutdown"));
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn unresponsive_owned_child_is_forced_and_reaped_within_budget() {
        let mut control = Control {
            child: Some(fixture_child(true)),
            ..Control::default()
        };
        let began = Instant::now();
        stop_control_with_budget(
            &mut control,
            Duration::from_millis(50),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(control.child.is_none());
        assert!(began.elapsed() < Duration::from_secs(3));
    }

    #[cfg(windows)]
    #[test]
    fn forced_owned_tree_terminates_descendant_and_its_actual_listener() {
        use std::ffi::c_void;
        use std::os::windows::process::CommandExt;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
            fn WaitForSingleObject(handle: *mut c_void, timeout: u32) -> u32;
            fn TerminateProcess(handle: *mut c_void, code: u32) -> i32;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        struct OwnedDescendant(*mut c_void);
        impl Drop for OwnedDescendant {
            fn drop(&mut self) {
                unsafe {
                    if WaitForSingleObject(self.0, 0) == 258 {
                        // The handle pins only the descendant created by our
                        // fixture. It cannot target a reused numeric PID.
                        TerminateProcess(self.0, 99);
                        WaitForSingleObject(self.0, 5000);
                    }
                    CloseHandle(self.0);
                }
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let marker = std::env::temp_dir().join(format!(
            "lightwork-owned-tree-{}-{nonce}.txt",
            std::process::id()
        ));
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::child_fixture"])
            .env("LIGHTWORK_RUNTIME_TEST_CHILD", "tree")
            .env("LIGHTWORK_RUNTIME_TEST_MARKER", &marker)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .unwrap();
        let dashboard = Dashboard(Mutex::new(Control {
            child: Some(child),
            drain_timeout: Some(Duration::from_millis(50)),
            ..Control::default()
        }));
        let deadline = Instant::now() + Duration::from_secs(5);
        let (pid, address) = loop {
            if let Ok(details) = std::fs::read_to_string(&marker) {
                let mut lines = details.lines();
                if let (Some(pid), Some(address)) = (lines.next(), lines.next()) {
                    if let (Ok(pid), Ok(address)) =
                        (pid.parse::<u32>(), address.parse::<SocketAddr>())
                    {
                        break (pid, address);
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "owned descendant did not report ready"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        let process = unsafe { OpenProcess(0x0010_0001, 0, pid) };
        assert!(!process.is_null());
        let descendant = OwnedDescendant(process);
        assert_eq!(unsafe { WaitForSingleObject(descendant.0, 0) }, 258);
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok());
        let began = Instant::now();
        let (stopped, reaped, forced) = {
            let mut control = dashboard.0.lock().unwrap();
            let stopped = stop_control_with_budget(
                &mut control,
                Duration::from_millis(50),
                Duration::from_secs(2),
            );
            let forced = control
                .logs
                .lock()
                .unwrap()
                .contains("stopping the owned process tree");
            (stopped, control.child.is_none(), forced)
        };
        stopped.unwrap();
        assert!(reaped && forced);
        assert_eq!(unsafe { WaitForSingleObject(descendant.0, 1000) }, 0);
        assert!(wait_for_listener_exit(
            || TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok(),
            Duration::from_secs(1)
        ));
        assert!(began.elapsed() < Duration::from_secs(4));
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn maintenance_cannot_advance_while_an_actual_socket_outlives_owned_child() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let close = Arc::new(AtomicBool::new(false));
        let requested = Arc::clone(&close);
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !requested.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => drop(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("owned maintenance listener failed: {error}"),
                }
            }
        });
        let dashboard = Dashboard(Mutex::new(Control {
            child: Some(fixture_child(true)),
            drain_timeout: Some(Duration::ZERO),
            ..Control::default()
        }));
        let probe = || TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok();
        let result = dashboard.pause_for_maintenance_with(probe);
        let still_live = probe();
        close.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(result.unwrap_err().contains("Installation has not started"));
        assert!(still_live);
        assert!(dashboard.0.lock().unwrap().child.is_none());
        assert!(dashboard.pause_for_maintenance_with(probe).is_ok());
    }

    #[test]
    fn invalid_desktop_shutdown_policy_refuses_launch() {
        for value in ["", "NaN", "inf", "-1", "301"] {
            assert!(configured_drain_timeout(&[(
                "MAVERICK_SHUTDOWN_TIMEOUT".into(),
                value.into()
            )])
            .is_err());
        }
        assert_eq!(
            configured_drain_timeout(&[("MAVERICK_SHUTDOWN_TIMEOUT".into(), "0.25".into())])
                .unwrap(),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn running_owned_child_is_not_started_twice() {
        let dashboard = Dashboard::default();
        {
            let mut control = dashboard.0.lock().unwrap();
            ensure_started(&mut control, || false, |_| Ok(fixture_child(true))).unwrap();
            let pid = control.child.as_ref().unwrap().id();
            ensure_started(&mut control, || false, |_| panic!("duplicate launch")).unwrap();
            assert_eq!(control.child.as_ref().unwrap().id(), pid);
        }
        dashboard.stop_owned();
        assert!(dashboard.0.lock().unwrap().child.is_none());
    }

    #[test]
    fn exited_child_can_be_retried() {
        let mut control = Control::default();
        ensure_started(&mut control, || false, |_| Ok(fixture_child(false))).unwrap();
        control.child.as_mut().unwrap().wait().unwrap();
        let mut attempted = false;
        let result = ensure_started(
            &mut control,
            || false,
            |_| {
                attempted = true;
                Err("synthetic retry".into())
            },
        );
        assert!(attempted);
        assert!(result.is_err());
        assert!(control.child.is_none());
    }

    #[test]
    fn listening_dashboard_is_reused_without_spawning() {
        let mut control = Control::default();
        assert!(ensure_started(&mut control, || true, |_| panic!("must not launch")).is_ok());
        assert!(control.child.is_none());
    }

    #[test]
    fn failed_launch_is_retryable_and_keeps_diagnostics() {
        let mut control = Control::default();
        for _ in 0..2 {
            let result = ensure_started(
                &mut control,
                || false,
                |logs| {
                    record(logs, "Synthetic launch failure");
                    Err("Synthetic launch failure".into())
                },
            );
            assert!(result.is_err());
            assert!(control.child.is_none());
            assert!(control
                .logs
                .lock()
                .unwrap()
                .contains("Synthetic launch failure"));
        }
    }

    #[test]
    fn output_is_bounded_and_valid_utf8() {
        let logs = Logs::default();
        for _ in 0..100 {
            record(&logs, &"🔎".repeat(1000));
        }
        let log = logs.lock().unwrap();
        assert!(log.len() <= MAX_LOG_BYTES);
        assert!(log.ends_with('🔎'));
    }

    #[test]
    fn previous_attempt_cannot_write_into_retry_diagnostics() {
        let mut control = Control::default();
        let old_logs = Arc::clone(&control.logs);
        let _ = ensure_started(&mut control, || false, |_| Err("retry".into()));
        record(&old_logs, "late previous attempt");
        assert!(!control.logs.lock().unwrap().contains("previous attempt"));
    }
}
