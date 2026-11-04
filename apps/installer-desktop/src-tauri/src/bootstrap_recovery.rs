//! Durable, non-secret bootstrap progress and bounded local dependency inventory.
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

static JOURNAL_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Journal {
    pub schema: u8,
    pub source_ref: String,
    #[serde(default)]
    pub previous_source_ref: String,
    pub phase: String,
    pub outcome: String,
    pub previous_outcome: String,
    pub updated_at: u64,
    pub review: String,
    pub inventory: Vec<Dependency>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub state: String,
    pub detail: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn path(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    Ok(root.join("bootstrap-recovery.json"))
}
fn read(app: &AppHandle) -> Result<Journal, String> {
    let file = path(app)?;
    if !file.exists() {
        return Ok(Journal::default());
    }
    if std::fs::symlink_metadata(&file)
        .map_err(|e| e.to_string())?
        .len()
        > 16384
        || file.is_symlink()
    {
        return Err("The bootstrap recovery journal needs administrator inspection.".into());
    }
    serde_json::from_slice(&std::fs::read(file).map_err(|e| e.to_string())?).map_err(|_| "The saved bootstrap state is unreadable. Review the installed dependencies with your administrator before resetting the journal.".into())
}
fn write(app: &AppHandle, row: &Journal) -> Result<(), String> {
    let target = path(app)?;
    let mut file =
        tempfile::NamedTempFile::new_in(target.parent().ok_or("Recovery directory unavailable.")?)
            .map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(row).map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("Bootstrap inventory exceeds its limit.".into());
    }
    file.write_all(&bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    file.persist(target).map_err(|e| e.to_string())?;
    Ok(())
}

async fn probe(name: &str, program: &str, args: &[&str]) -> Dependency {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(0x08000004); // hidden + suspended until owned job attached
    let failed = |detail: &str| Dependency {
        name: name.into(),
        state: "unconfirmed".into(),
        detail: detail.into(),
    };
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Dependency {
                name: name.into(),
                state: if error.kind() == std::io::ErrorKind::NotFound {
                    "missing"
                } else {
                    "unconfirmed"
                }
                .into(),
                detail: "The dependency could not be started from this installer environment."
                    .into(),
            }
        }
    };
    let Some(pid) = child.id() else {
        return failed("The dependency probe has no process identity.");
    };
    let mut tree = match super::ProcessTreeGuard::attach(pid) {
        Ok(tree) => tree,
        Err(_) => {
            let _ = child.kill().await;
            return failed("Could not establish process ownership for this check.");
        }
    };
    let Some(output) = child.stdout.take() else {
        let _ = tree.terminate_hard();
        return failed("The dependency response is unavailable.");
    };
    let reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        output
            .take(4097)
            .read_to_end(&mut bytes)
            .await
            .map(|_| bytes)
    });
    let result = tokio::time::timeout(Duration::from_secs(8), child.wait()).await;
    if !matches!(&result, Ok(Ok(status)) if status.success()) {
        let _ = tree.terminate_hard();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        let _ = super::verify_process_tree(&mut tree, false).await;
        reader.abort();
        return failed(
            "The local check failed or exceeded eight seconds. Repair or recheck before resuming.",
        );
    }
    if super::verify_process_tree(&mut tree, false).await.is_err() {
        reader.abort();
        return failed("Dependency probe cleanup could not be confirmed.");
    }
    let bytes = match tokio::time::timeout(Duration::from_secs(1), reader).await {
        Ok(Ok(Ok(bytes))) if bytes.len() <= 4096 => bytes,
        _ => return failed("The dependency response exceeded its bound."),
    };
    let text: String = String::from_utf8_lossy(&bytes)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(1200)
        .collect();
    Dependency {
        name: name.into(),
        state: if text.contains("not installed") {
            "partial"
        } else {
            "responded"
        }
        .into(),
        detail: text,
    }
}

pub async fn inventory(app: &AppHandle) -> Result<Journal, String> {
    let old = {
        let _guard = JOURNAL_LOCK
            .lock()
            .map_err(|_| "Inventory lock unavailable.")?;
        read(app)?
    };
    let (git, mut python, pipx, lightwork) = tokio::join!(probe("Git", "git", &["--version"]), probe("Python", "python3", &["-I", "-S", "-c", "import sys; print(sys.version.split()[0]); sys.exit(0 if sys.version_info >= (3,11) else 1)"]), probe("pipx", "pipx", &["--version"]), probe("Lightwork package cohort", "maverick", &["version"]));
    if python.state != "responded" {
        python = probe("Python", "python", &["-I", "-S", "-c", "import sys; print(sys.version.split()[0]); sys.exit(0 if sys.version_info >= (3,11) else 1)"]).await;
    }
    let _guard = JOURNAL_LOCK
        .lock()
        .map_err(|_| "Inventory lock unavailable.")?;
    let report = Journal {
        schema: 1,
        source_ref: super::GIT_REF.into(),
        previous_source_ref: if old.outcome == "reviewed" {
            old.previous_source_ref
        } else {
            old.source_ref
        },
        phase: old.phase,
        previous_outcome: if old.outcome == "reviewed" {
            old.previous_outcome
        } else {
            old.outcome
        },
        outcome: "reviewed".into(),
        updated_at: now(),
        review: format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ),
        inventory: vec![git, python, pipx, lightwork],
    };
    write(app, &report)?;
    Ok(report)
}

pub fn begin(app: &AppHandle, review: &str, confirm: bool) -> Result<(), String> {
    let _guard = JOURNAL_LOCK
        .lock()
        .map_err(|_| "Inventory lock unavailable.")?;
    let mut row = read(app)?;
    if row.outcome != "reviewed"
        || row.review != review
        || review.is_empty()
        || row.source_ref != super::GIT_REF
        || now().saturating_sub(row.updated_at) > 300
    {
        return Err(
            "Recheck local dependencies and review this exact bootstrap before starting.".into(),
        );
    }
    if !row.previous_outcome.is_empty() && row.previous_outcome != "completed" && !confirm {
        return Err("Confirm that any package-manager or elevation operation has finished, and review partial dependencies before resuming.".into());
    }
    row.outcome = "running".into();
    row.review.clear();
    row.updated_at = now();
    row.phase = "preflight complete".into();
    write(app, &row)
}

pub fn mark(app: &AppHandle, outcome: &str) -> Result<(), String> {
    let _guard = JOURNAL_LOCK
        .lock()
        .map_err(|_| "Inventory lock unavailable.")?;
    let mut row = read(app)?;
    row.outcome = outcome.into();
    row.review.clear();
    row.updated_at = now();
    write(app, &row)
}
pub fn progress(app: &AppHandle, text: &str) -> Result<(), String> {
    let phase = if text.contains("Installing the complete Lightwork package") {
        "installing complete package cohort"
    } else if text.contains("Downloading a fresh Lightwork") {
        "downloading pinned source"
    } else if text.contains("Installing")
        || text.contains("Ensuring pipx")
        || text.contains("Using Python")
    {
        "preparing dependencies"
    } else {
        return Ok(());
    };
    let _guard = JOURNAL_LOCK
        .lock()
        .map_err(|_| "Inventory lock unavailable.")?;
    let mut row = read(app)?;
    if row.phase == phase {
        return Ok(());
    }
    row.phase = phase.into();
    row.updated_at = now();
    write(app, &row)
}

#[cfg(test)]
mod tests {
    #[test]
    fn journal_round_trip_preserves_partial_inventory_without_logs() {
        let row = super::Journal {
            schema: 1,
            outcome: "cleanup_uncertain".into(),
            source_ref: "a".repeat(40),
            inventory: vec![super::Dependency {
                name: "Python".into(),
                state: "partial".into(),
                detail: "Needs OS repair".into(),
            }],
            ..Default::default()
        };
        let restored: super::Journal =
            serde_json::from_slice(&serde_json::to_vec(&row).unwrap()).unwrap();
        assert_eq!(restored.outcome, "cleanup_uncertain");
        assert_eq!(restored.inventory[0].state, "partial");
    }
}
