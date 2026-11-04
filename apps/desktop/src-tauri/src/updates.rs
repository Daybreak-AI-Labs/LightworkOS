//! User-reviewed maintenance for the packaged Windows application.
//! The download address and verification key come only from the compiled
//! release configuration. Dashboard content cannot select an installer.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::Mutex;
use tauri::Manager;

#[derive(Default)]
pub struct Maintenance {
    busy: AtomicBool,
    #[cfg(windows)]
    pending: Mutex<Option<(String, tauri_plugin_updater::Update, bool)>>,
    #[cfg(windows)]
    sequence: Mutex<u64>,
    #[cfg(windows)]
    handoff: Mutex<Option<String>>,
}

struct Busy<'a>(&'a AtomicBool);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn acquire(state: &Maintenance) -> Result<Busy<'_>, String> {
    state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "Another maintenance operation is still running.")?;
    Ok(Busy(&state.busy))
}

fn local_controls(window: &tauri::WebviewWindow) -> Result<(), String> {
    let url = window
        .url()
        .map_err(|_| "The maintenance window is unavailable.")?;
    let expected = super::bundled_page_url("maintenance.html");
    if url != expected {
        return Err("Open Install & updates from the Lightwork app menu.".into());
    }
    Ok(())
}

fn reviewed_authorization(state: &Maintenance, manual: Option<String>) -> Result<String, String> {
    if let Some(value) = manual.filter(|value| !value.trim().is_empty()) {
        return Ok(value);
    }
    #[cfg(windows)]
    {
        state
            .handoff
            .lock()
            .map_err(|_| "Maintenance approval is unavailable.")?
            .take()
            .ok_or_else(|| {
                "Load the protected administrator handoff or paste its accessible fallback code."
                    .into()
            })
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Err("In-app maintenance is currently supported on Windows.".into())
    }
}

#[tauri::command]
pub fn review_maintenance_handoff(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
) -> Result<serde_json::Value, String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    #[cfg(windows)]
    {
        let runtime = maintenance_runtime_path()?;
        let mut details = protocol(&runtime, "inspect-handoff", &serde_json::json!({}))?;
        let token = details
            .get("authorization")
            .and_then(|value| value.as_str())
            .ok_or("The protected handoff is incomplete.")?
            .to_string();
        *state
            .handoff
            .lock()
            .map_err(|_| "Maintenance approval is unavailable.")? = Some(token);
        if let Some(object) = details.as_object_mut() {
            for key in ["authorization", "actor", "schema", "target"] {
                object.remove(key);
            }
        }
        Ok(details)
    }
    #[cfg(not(windows))]
    {
        Err("In-app maintenance is currently supported on Windows.".into())
    }
}

#[derive(Serialize)]
pub struct MaintenanceStatus {
    version: String,
    packaged_runtime: bool,
    updates_configured: bool,
    recovery: serde_json::Value,
    reviewed_update: Option<ReviewedUpdate>,
}

fn channel_configured(app: &tauri::AppHandle) -> bool {
    let Some(config) = app.config().plugins.0.get("updater") else {
        return false;
    };
    let key_present = config
        .get("pubkey")
        .and_then(|v| v.as_str())
        .is_some_and(|key| !key.trim().is_empty());
    let endpoints_valid = config
        .get("endpoints")
        .and_then(|v| v.as_array())
        .is_some_and(|items| {
            !items.is_empty()
                && items.iter().all(|item| {
                    item.as_str()
                        .and_then(|text| tauri::Url::parse(text).ok())
                        .is_some_and(|url| {
                            url.scheme() == "https"
                                && url.host_str().is_some()
                                && url.username().is_empty()
                                && url.password().is_none()
                                && url.fragment().is_none()
                        })
                })
        });
    cfg!(all(windows, feature = "customer-runtime")) && key_present && endpoints_valid
}

#[tauri::command]
pub fn maintenance_status(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<MaintenanceStatus, String> {
    local_controls(&window)?;
    Ok(MaintenanceStatus {
        version: app.package_info().version.to_string(),
        packaged_runtime: cfg!(feature = "customer-runtime"),
        updates_configured: channel_configured(&app),
        reviewed_update: pending_review(&app.state::<Maintenance>())?,
        recovery: if cfg!(feature = "customer-runtime") {
            selected_maintenance_runtime()
                .map(|(_, status)| status)
                .unwrap_or_else(|error| {
                    serde_json::json!({"recovery_points": [], "unavailable": true, "detail": error})
                })
        } else {
            serde_json::json!({"recovery_points": [], "incomplete": false})
        },
    })
}

#[derive(Serialize)]
pub struct ReviewedUpdate {
    review: String,
    version: String,
    current_version: String,
    notes: String,
    repair: bool,
    identity_transition: Option<serde_json::Value>,
}

fn pending_review(state: &Maintenance) -> Result<Option<ReviewedUpdate>, String> {
    #[cfg(windows)]
    {
        let pending = state
            .pending
            .lock()
            .map_err(|_| "Update state is unavailable.")?;
        Ok(pending
            .as_ref()
            .map(|(review, update, repair)| ReviewedUpdate {
                review: review.clone(),
                version: update.version.clone(),
                current_version: update.current_version.clone(),
                notes: update
                    .body
                    .clone()
                    .unwrap_or_default()
                    .chars()
                    .take(16_000)
                    .collect(),
                repair: *repair,
                identity_transition: update
                    .raw_json
                    .get("identity_transition")
                    .filter(|v| !v.is_null())
                    .cloned(),
            }))
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Ok(None)
    }
}

fn manifest_sha256(
    raw: &serde_json::Value,
    name: &str,
    description: &str,
) -> Result<String, String> {
    let value = raw
        .get(name)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("The repair release lacks its exact {description} identity."))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "The repair release has an invalid {description} identity."
        ));
    }
    Ok(value.to_string())
}

fn repair_download_metadata(
    raw: &serde_json::Value,
    version: &str,
    signature: &str,
    public_key: &str,
) -> Result<serde_json::Value, String> {
    if version.is_empty()
        || signature.is_empty()
        || signature.len() > 16_384
        || public_key.trim().is_empty()
        || public_key.len() > 4_096
        || raw
            .get("identity_transition")
            .is_some_and(|value| !value.is_null())
    {
        return Err(
            "The same-version repair identity is incomplete or proposes a trust change.".into(),
        );
    }
    Ok(serde_json::json!({
        "public_key": public_key,
        "identity_transition": null,
        "new": {
            "version": version,
            "signature": signature,
            "runtime_sha256": manifest_sha256(raw, "runtime_sha256", "runtime")?,
            "installer_sha256": manifest_sha256(raw, "installer_sha256", "installer")?,
        }
    }))
}

fn repair_authorization_request(metadata: &serde_json::Value) -> Result<serde_json::Value, String> {
    let release = metadata
        .get("new")
        .ok_or("The verified repair release identity is unavailable.")?;
    let version = release
        .get("version")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or("The verified repair release version is unavailable.")?;
    let public_key = metadata
        .get("public_key")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty() && value.len() <= 4_096)
        .ok_or("The verified repair signing identity is unavailable.")?;
    Ok(serde_json::json!({
        "confirm": true,
        "version": version,
        "runtime_sha256": manifest_sha256(release, "runtime_sha256", "runtime")?,
        "installer_sha256": manifest_sha256(release, "installer_sha256", "installer")?,
        "public_key": public_key,
    }))
}

#[tauri::command]
pub async fn check_desktop_update(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    repair: bool,
) -> Result<Option<ReviewedUpdate>, String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    if !channel_configured(&app) {
        return Err("This build has no verified update channel. In-app updates are available only in a signed packaged build configured with an update channel.".into());
    }
    #[cfg(windows)]
    {
        use tauri_plugin_updater::UpdaterExt;
        *state
            .pending
            .lock()
            .map_err(|_| "Update state is unavailable.")? = None;
        let app_for_exit = app.clone();
        let mut builder = app
            .updater_builder()
            .timeout(std::time::Duration::from_secs(30))
            .on_before_exit(move || {
                app_for_exit
                    .state::<lightwork_desktop_runtime::Dashboard>()
                    .stop_owned();
            });
        if repair {
            builder = builder
                .endpoints(version_endpoints(
                    &app,
                    &app.package_info().version.to_string(),
                )?)
                .map_err(|e| e.to_string())?
                .version_comparator(|current, release| release.version == current);
        }
        let update = builder
            .build()
            .map_err(|e| e.to_string())?
            .check()
            .await
            .map_err(|e| e.to_string())?;
        if let Some(update) = update {
            let transition = update
                .raw_json
                .get("identity_transition")
                .filter(|value| !value.is_null())
                .cloned();
            if transition
                .as_ref()
                .is_some_and(|value| repair || value.to_string().len() > 65536)
            {
                return Err("A signing identity transition requires a bounded, reviewed protected upgrade; it cannot use repair.".into());
            }
            // Signatures are mandatory, independently of HTTPS. Refuse unsafe
            // metadata URLs before any artifact download as defense in depth.
            if update.download_url.scheme() != "https"
                || !update.download_url.username().is_empty()
                || update.download_url.password().is_some()
            {
                return Err("The update download address is not an approved HTTPS address.".into());
            }
            let mut sequence = state
                .sequence
                .lock()
                .map_err(|_| "Update state is unavailable.")?;
            *sequence += 1;
            let review = sequence.to_string();
            if !repair {
                let runtime = maintenance_runtime_path()?;
                protocol(
                    &runtime,
                    "save-native-review",
                    &serde_json::json!({
                        "release": {"version": update.version, "signature": update.signature,
                            "runtime_sha256": manifest_sha256(&update.raw_json, "runtime_sha256", "runtime")?,
                            "installer_sha256": manifest_sha256(&update.raw_json, "installer_sha256", "installer")?}
                    }),
                )?;
            }
            let result = ReviewedUpdate {
                review: review.clone(),
                version: update.version.clone(),
                current_version: update.current_version.clone(),
                notes: update
                    .body
                    .clone()
                    .unwrap_or_default()
                    .chars()
                    .take(16_000)
                    .collect(),
                repair,
                identity_transition: transition,
            };
            *state
                .pending
                .lock()
                .map_err(|_| "Update state is unavailable.")? = Some((review, update, repair));
            return Ok(Some(result));
        }
        Ok(None)
    }
    #[cfg(not(windows))]
    {
        let _ = repair;
        Err("In-app maintenance is currently supported on Windows.".into())
    }
}

#[tauri::command]
pub async fn install_desktop_update(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    review: String,
    confirm: bool,
    authorization: Option<String>,
) -> Result<(), String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    if !confirm {
        return Err("Review and confirm the installation first.".into());
    }
    #[cfg(windows)]
    {
        let update = {
            let mut pending = state
                .pending
                .lock()
                .map_err(|_| "Update state is unavailable.")?;
            if pending.as_ref().map(|(id, _, _)| id.as_str()) != Some(review.as_str()) {
                return Err(
                    "This update review has expired. Check again before installing.".into(),
                );
            }
            if !pending.as_ref().expect("checked pending update").2 {
                let candidate = authorization
                    .clone()
                    .filter(|value| !value.is_empty())
                    .or_else(|| state.handoff.lock().ok().and_then(|value| value.clone()))
                    .ok_or("Load a current administrator approval first.")?;
                let runtime = maintenance_runtime_path()?;
                protocol(
                    &runtime,
                    "inspect",
                    &serde_json::json!({"authorization": candidate}),
                )?;
            }
            pending.take().expect("checked pending update")
        };
        let (_, update, repair) = update;
        if repair {
            let key = app
                .config()
                .plugins
                .0
                .get("updater")
                .and_then(|value| value.get("pubkey"))
                .and_then(|value| value.as_str())
                .ok_or("The release verification key is missing.")?;
            let metadata = repair_download_metadata(
                &update.raw_json,
                &update.version,
                &update.signature,
                key,
            )?;
            let bytes = download_bounded(&update).await?;
            // A malformed manifest or failed network/signature check must not
            // consume one of the bounded local recovery points. Create the
            // signed repair authorization only after immutable bytes exist.
            let authorization_request = repair_authorization_request(&metadata)?;
            let (runtime, _) = selected_repair_runtime(&authorization_request)?;
            let grant = protocol(&runtime, "authorize-repair", &authorization_request)?;
            if grant["operation"] != "repair" || grant["old_version"] != update.current_version {
                return Err(
                    "The repair authorization does not match the installed release.".into(),
                );
            }
            let authorization = grant["authorization"]
                .as_str()
                .ok_or("The private repair authorization is unavailable.")?;
            let directory = std::path::PathBuf::from(
                grant["directory"]
                    .as_str()
                    .ok_or("The private repair directory is unavailable.")?,
            );
            std::fs::write(directory.join("new.msi"), bytes).map_err(|error| error.to_string())?;
            std::fs::write(
                directory.join("downloads.json"),
                serde_json::to_vec(&metadata).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            app.state::<lightwork_desktop_runtime::Dashboard>()
                .pause_for_maintenance()?;
            let prepared = protocol(
                &runtime,
                "prepare",
                &serde_json::json!({"authorization": authorization}),
            )?;
            launch_operation(&app, &prepared, authorization)?;
            return Ok(());
        } else {
            use tauri_plugin_updater::UpdaterExt;
            let authorization = reviewed_authorization(&state, authorization)?;
            let runtime = maintenance_runtime_path()?;
            let details = protocol(
                &runtime,
                "inspect",
                &serde_json::json!({"authorization": authorization}),
            )?;
            if details["operation"] != "upgrade" || details["old_version"] != update.current_version
            {
                return Err("The authorization does not match the reviewed installation.".into());
            }
            if let Some(reviewed) = details.get("reviewed_new").filter(|value| !value.is_null()) {
                if reviewed["version"] != update.version
                    || reviewed["signature"] != update.signature
                    || reviewed["runtime_sha256"] != update.raw_json["runtime_sha256"]
                    || reviewed["installer_sha256"] != update.raw_json["installer_sha256"]
                {
                    return Err("The administrator handoff is for a different exact release. Review this update again.".into());
                }
            }
            let transition = update
                .raw_json
                .get("identity_transition")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            if details["identity_transition"] != transition {
                return Err("The offered signing identity transition differs from the administrator's exact review.".into());
            }
            let old = app.updater_builder()
                .endpoints(version_endpoints(&app, &update.current_version)?).map_err(|e| e.to_string())?
                .version_comparator(|current, release| release.version == current)
                .timeout(std::time::Duration::from_secs(30))
                .build().map_err(|e| e.to_string())?.check().await.map_err(|e| e.to_string())?
                .ok_or("The exact installed release is unavailable. A protected upgrade requires its verified rollback installer.")?;
            let directory = std::path::PathBuf::from(
                details["directory"]
                    .as_str()
                    .ok_or("The private recovery directory is unavailable.")?,
            );
            let key = app
                .config()
                .plugins
                .0
                .get("updater")
                .and_then(|v| v.get("pubkey"))
                .and_then(|v| v.as_str())
                .ok_or("The release verification key is missing.")?;
            let mut metadata =
                serde_json::json!({"public_key": key, "identity_transition": transition});
            for (name, release) in [("old", &old), ("new", &update)] {
                if release.download_url.scheme() != "https"
                    || !release.download_url.username().is_empty()
                    || release.download_url.password().is_some()
                {
                    return Err("The retained installer address is not approved HTTPS.".into());
                }
                let bytes = download_bounded(release).await?;
                std::fs::write(directory.join(format!("{name}.msi")), bytes)
                    .map_err(|e| e.to_string())?;
                metadata[name] = serde_json::json!({"version": release.version, "signature": release.signature,
                    "runtime_sha256": release.raw_json.get("runtime_sha256")});
            }
            std::fs::write(
                directory.join("downloads.json"),
                serde_json::to_vec(&metadata).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            app.state::<lightwork_desktop_runtime::Dashboard>()
                .pause_for_maintenance()?;
            let prepared = protocol(
                &runtime,
                "prepare",
                &serde_json::json!({"authorization": authorization}),
            )?;
            launch_operation(&app, &prepared, &authorization)?;
            return Ok(());
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (app, review, authorization);
        Err("In-app maintenance is currently supported on Windows.".into())
    }
}

#[tauri::command]
pub fn desktop_maintenance_logs(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    id: String,
) -> Result<serde_json::Value, String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    let (runtime, _) = selected_maintenance_runtime()?;
    protocol(&runtime, "logs", &serde_json::json!({"id": id}))
}

#[tauri::command]
pub fn desktop_recovery_plan(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    id: String,
    offset: usize,
) -> Result<serde_json::Value, String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    let (runtime, _) = selected_maintenance_runtime()?;
    protocol(
        &runtime,
        "recovery-plan",
        &serde_json::json!({"id": id, "offset": offset}),
    )
}

#[tauri::command]
pub fn review_offline_repair(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    folder: String,
) -> Result<serde_json::Value, String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    if !cfg!(all(windows, feature = "customer-runtime")) {
        return Err("Offline repair is currently supported on Windows.".into());
    }
    let key = app
        .config()
        .plugins
        .0
        .get("updater")
        .and_then(|v| v.get("pubkey"))
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or("This build has no pinned release verification key.")?;
    let (runtime, _) = selected_maintenance_runtime()?;
    protocol(
        &runtime,
        "offline-review",
        &serde_json::json!({"folder": folder, "public_key": key}),
    )
}

#[tauri::command]
pub fn install_offline_repair(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    review: String,
    confirm: bool,
) -> Result<(), String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    if !confirm {
        return Err("Review and explicitly confirm the offline repair first.".into());
    }
    #[cfg(windows)]
    {
        let (runtime, _) = selected_maintenance_runtime()?;
        let grant = protocol(
            &runtime,
            "offline-authorize",
            &serde_json::json!({"review": review, "confirm": true}),
        )?;
        let authorization = grant
            .get("authorization")
            .and_then(|v| v.as_str())
            .ok_or("The offline repair approval is unavailable.")?;
        app.state::<lightwork_desktop_runtime::Dashboard>()
            .pause_for_maintenance()?;
        let prepared = protocol(
            &runtime,
            "prepare",
            &serde_json::json!({"authorization": authorization}),
        )?;
        launch_operation(&app, &prepared, authorization)
    }
    #[cfg(not(windows))]
    {
        let _ = (app, review);
        Err("Offline repair is currently supported on Windows.".into())
    }
}

fn recovery_runtime_for(executable: &std::path::Path) -> Result<std::path::PathBuf, String> {
    Ok(executable
        .parent()
        .ok_or("The installed application directory is unavailable.")?
        .join("maverick-recovery.exe"))
}

fn primary_runtime_for(executable: &std::path::Path) -> Result<std::path::PathBuf, String> {
    Ok(executable
        .parent()
        .ok_or("The installed application directory is unavailable.")?
        .join("maverick.exe"))
}

fn maintenance_runtime_candidates(
    executable: &std::path::Path,
) -> Result<[std::path::PathBuf; 2], String> {
    Ok([
        recovery_runtime_for(executable)?,
        primary_runtime_for(executable)?,
    ])
}

fn valid_maintenance_status(value: &serde_json::Value) -> bool {
    value
        .get("maintenance_protocol")
        .and_then(|value| value.as_u64())
        == Some(2)
        && value
            .get("recovery_points")
            .is_some_and(serde_json::Value::is_array)
        && value
            .get("incomplete")
            .is_some_and(serde_json::Value::is_boolean)
}

fn valid_windows_product_code(value: &serde_json::Value) -> bool {
    let Some(value) = value.as_str() else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 38
        && bytes[0] == b'{'
        && bytes[37] == b'}'
        && [9, 14, 19, 24]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[1..37]
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn valid_repair_capability(
    value: &serde_json::Value,
    request: &serde_json::Value,
    candidate: &std::path::Path,
) -> bool {
    let expected_role = if candidate.ends_with("maverick-recovery.exe") {
        "recovery"
    } else if candidate.ends_with("maverick.exe") {
        "primary"
    } else {
        return false;
    };
    value.get("schema").and_then(|item| item.as_str())
        == Some("lightwork.installation-repair-capability.v1")
        && value.get("compatible").and_then(|item| item.as_bool()) == Some(true)
        && value.get("runtime_role").and_then(|item| item.as_str()) == Some(expected_role)
        && [
            "version",
            "runtime_sha256",
            "installer_sha256",
            "public_key",
        ]
        .into_iter()
        .all(|name| {
            request
                .get(name)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|expected| {
                    value.get(name).and_then(serde_json::Value::as_str) == Some(expected)
                })
        })
        && value
            .get("retained_installer_available")
            .is_some_and(serde_json::Value::is_boolean)
        && value
            .get("product_code")
            .is_some_and(valid_windows_product_code)
        && value
            .get("package_code")
            .is_some_and(valid_windows_product_code)
}

fn select_maintenance_runtime_with<F>(
    executable: &std::path::Path,
    mut probe: F,
) -> Result<(std::path::PathBuf, serde_json::Value), String>
where
    F: FnMut(&std::path::Path) -> Result<serde_json::Value, String>,
{
    let candidates = maintenance_runtime_candidates(executable)?;
    let mut failures = Vec::new();
    for (description, candidate) in ["retained", "primary"].into_iter().zip(candidates) {
        match probe(&candidate) {
            Ok(status) if valid_maintenance_status(&status) => return Ok((candidate, status)),
            Ok(_) => failures.push(format!(
                "The {description} maintenance runtime returned an incomplete status response."
            )),
            Err(error) => failures.push(format!(
                "The {description} maintenance runtime could not start: {}",
                error.chars().take(2000).collect::<String>()
            )),
        }
    }
    Err(format!(
        "No packaged maintenance runtime is available. {}",
        failures.join(" ")
    ))
}

fn selected_maintenance_runtime() -> Result<(std::path::PathBuf, serde_json::Value), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    select_maintenance_runtime_with(&executable, |candidate| {
        protocol(candidate, "status", &serde_json::json!({}))
    })
}

fn select_repair_runtime_with<F>(
    executable: &std::path::Path,
    request: &serde_json::Value,
    mut probe: F,
) -> Result<(std::path::PathBuf, serde_json::Value), String>
where
    F: FnMut(&std::path::Path, &serde_json::Value) -> Result<serde_json::Value, String>,
{
    let candidates = maintenance_runtime_candidates(executable)?;
    let mut failures = Vec::new();
    for (description, candidate) in ["retained", "primary"].into_iter().zip(candidates) {
        match probe(&candidate, request) {
            Ok(capability) if valid_repair_capability(&capability, request, &candidate) => {
                return Ok((candidate, capability));
            }
            Ok(_) => failures.push(format!(
                "The {description} maintenance runtime does not match this signed repair release."
            )),
            Err(error) => failures.push(format!(
                "The {description} maintenance runtime cannot prepare this repair: {}",
                error.chars().take(2000).collect::<String>()
            )),
        }
    }
    Err(format!(
        "No packaged runtime matches this signed repair release. {}",
        failures.join(" ")
    ))
}

fn selected_repair_runtime(
    request: &serde_json::Value,
) -> Result<(std::path::PathBuf, serde_json::Value), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    select_repair_runtime_with(&executable, request, |candidate, request| {
        protocol(candidate, "repair-capability", request)
    })
}

fn maintenance_runtime_path() -> Result<std::path::PathBuf, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    recovery_runtime_for(&executable)
}

#[cfg(windows)]
async fn download_bounded(update: &tauri_plugin_updater::Update) -> Result<Vec<u8>, String> {
    const LIMIT: usize = 1024 * 1024 * 1024;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut sender = Some(sender);
    let mut received = 0usize;
    let download = update.download(
        move |chunk, announced| {
            received = received.saturating_add(chunk);
            if received > LIMIT || announced.is_some_and(|size| size > LIMIT as u64) {
                if let Some(sender) = sender.take() {
                    let _ = sender.send(());
                }
            }
        },
        || {},
    );
    tokio::select! {
        biased;
        result = download => {
            let bytes = result.map_err(|e| e.to_string())?;
            if bytes.len() > LIMIT { Err("The installer exceeds the maintenance size limit.".into()) } else { Ok(bytes) }
        },
        _ = receiver => Err("The installer exceeds the maintenance size limit.".into()),
    }
}

fn protocol(
    binary: &std::path::Path,
    step: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    use std::process::Command;

    let mut command = Command::new(binary);
    command.args(["installation-maintenance", step]);
    let payload = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let output = run_protocol_command(command, &payload, protocol_timeout(step))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(16000)
            .collect());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "The maintenance response could not be verified.".into())
}

const PROTOCOL_STDOUT_LIMIT: u64 = 256 * 1024;
const PROTOCOL_STDERR_LIMIT: u64 = 16 * 1024;
const PROTOCOL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn protocol_timeout(step: &str) -> std::time::Duration {
    match step {
        // Repair authorization verifies the registered package and retained
        // Authenticode source. Each native inspection has its own shorter cap.
        "repair-capability" | "authorize-repair" | "offline-review" | "offline-authorize"
        | "recovery-plan" => std::time::Duration::from_secs(6 * 60),
        // Preparing a protected operation can snapshot up to the documented
        // local recovery limit on a slow customer disk.
        "prepare" => std::time::Duration::from_secs(60 * 60),
        _ => std::time::Duration::from_secs(60),
    }
}

#[derive(Debug)]
struct ProtocolOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn bounded_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    limit: u64,
) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    use std::io::Read;

    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    receiver
}

fn receive_protocol_output(
    receiver: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    limit: u64,
    stream: &str,
) -> Result<Vec<u8>, String> {
    let bytes = receiver
        .recv_timeout(PROTOCOL_DRAIN_TIMEOUT)
        .map_err(|_| format!("The maintenance {stream} stream did not close safely."))?
        .map_err(|_| format!("The maintenance {stream} stream could not be read."))?;
    if bytes.len() as u64 > limit {
        return Err(format!("The maintenance {stream} exceeded its size limit."));
    }
    Ok(bytes)
}

fn run_protocol_command(
    mut command: std::process::Command,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<ProtocolOutput, String> {
    use std::io::Write;
    use std::process::Stdio;

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Suspend before first instruction so the process cannot escape the
        // kill-on-close Job Object by creating a descendant before assignment.
        command.creation_flags(0x0800_0000 | 0x0000_0004);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or("The maintenance response stream is unavailable.")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("The maintenance error stream is unavailable.")?;
    let stdout = bounded_reader(stdout, PROTOCOL_STDOUT_LIMIT);
    let stderr = bounded_reader(stderr, PROTOCOL_STDERR_LIMIT);
    let mut tree = match ProtocolProcessTree::attach(&child) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let write_result = child
        .stdin
        .take()
        .ok_or("The maintenance request stream is unavailable.")?
        .write_all(payload);
    if write_result.is_err() {
        let _ = tree.terminate();
        let _ = child.kill();
        let _ = child.wait();
        tree.disarm();
        return Err("The maintenance request could not be delivered.".into());
    }

    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        let status = child.try_wait().map_err(|e| e.to_string())?;
        if status.is_some() && tree.active_processes()? == 0 {
            break status.expect("checked process status");
        }
        if std::time::Instant::now() >= deadline {
            let terminated = tree.terminate();
            let _ = child.kill();
            let _ = child.wait();
            tree.disarm();
            return match terminated {
                Ok(()) => Err("The maintenance helper exceeded its time limit and was stopped.".into()),
                Err(_) => Err("The maintenance helper exceeded its time limit and could not be stopped safely.".into()),
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    tree.disarm();
    Ok(ProtocolOutput {
        status,
        stdout: receive_protocol_output(stdout, PROTOCOL_STDOUT_LIMIT, "response")?,
        stderr: receive_protocol_output(stderr, PROTOCOL_STDERR_LIMIT, "error")?,
    })
}

#[cfg(not(windows))]
struct ProtocolProcessTree;

#[cfg(not(windows))]
impl ProtocolProcessTree {
    fn attach(_child: &std::process::Child) -> Result<Self, String> {
        Ok(Self)
    }

    fn active_processes(&self) -> Result<u32, String> {
        Ok(0)
    }

    fn terminate(&self) -> Result<(), String> {
        Ok(())
    }

    fn disarm(&mut self) {}
}

#[cfg(windows)]
struct ProtocolProcessTree {
    job: usize,
    armed: bool,
}

#[cfg(windows)]
#[allow(non_snake_case)]
#[repr(C)]
struct JobObjectBasicLimitInformation {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: u32,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: u32,
    Affinity: usize,
    PriorityClass: u32,
    SchedulingClass: u32,
}

#[cfg(windows)]
#[allow(non_snake_case)]
#[repr(C)]
struct IoCounters {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
}

#[cfg(windows)]
#[allow(non_snake_case)]
#[repr(C)]
struct JobObjectExtendedLimitInformation {
    BasicLimitInformation: JobObjectBasicLimitInformation,
    IoInfo: IoCounters,
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryUsed: usize,
    PeakJobMemoryUsed: usize,
}

#[cfg(windows)]
#[allow(non_snake_case)]
#[repr(C)]
struct JobObjectBasicAccountingInformation {
    TotalUserTime: i64,
    TotalKernelTime: i64,
    ThisPeriodTotalUserTime: i64,
    ThisPeriodTotalKernelTime: i64,
    TotalPageFaultCount: u32,
    TotalProcesses: u32,
    ActiveProcesses: u32,
    TotalTerminatedProcesses: u32,
}

#[cfg(windows)]
#[allow(non_snake_case)]
#[repr(C)]
struct ThreadEntry32 {
    dwSize: u32,
    cntUsage: u32,
    th32ThreadID: u32,
    th32OwnerProcessID: u32,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(
        job_attributes: *const std::ffi::c_void,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn SetInformationJobObject(
        job: *mut std::ffi::c_void,
        information_class: i32,
        information: *const std::ffi::c_void,
        information_length: u32,
    ) -> i32;
    fn AssignProcessToJobObject(job: *mut std::ffi::c_void, process: *mut std::ffi::c_void) -> i32;
    fn QueryInformationJobObject(
        job: *mut std::ffi::c_void,
        information_class: i32,
        information: *mut std::ffi::c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn TerminateJobObject(job: *mut std::ffi::c_void, exit_code: u32) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut std::ffi::c_void;
    fn Thread32First(snapshot: *mut std::ffi::c_void, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: *mut std::ffi::c_void, entry: *mut ThreadEntry32) -> i32;
    fn OpenThread(
        desired_access: u32,
        inherit_handle: i32,
        thread_id: u32,
    ) -> *mut std::ffi::c_void;
    fn ResumeThread(thread: *mut std::ffi::c_void) -> u32;
}

#[cfg(windows)]
impl ProtocolProcessTree {
    fn attach(child: &std::process::Child) -> Result<Self, String> {
        use std::mem::{size_of, zeroed};
        use std::os::windows::io::AsRawHandle;
        use std::ptr;

        const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
        const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
        unsafe {
            let job = CreateJobObjectW(ptr::null(), ptr::null());
            if job.is_null() {
                return Err("The maintenance process tree could not be isolated.".into());
            }
            let mut information: JobObjectExtendedLimitInformation = zeroed();
            information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &information as *const _ as *const _,
                size_of::<JobObjectExtendedLimitInformation>() as u32,
            ) == 0
                || AssignProcessToJobObject(job, child.as_raw_handle() as *mut _) == 0
            {
                let _ = TerminateJobObject(job, 1);
                CloseHandle(job);
                return Err("The maintenance process tree could not be isolated.".into());
            }
            let mut tree = Self {
                job: job as usize,
                armed: true,
            };
            if let Err(error) = Self::resume_suspended_process(child.id()) {
                let _ = tree.terminate();
                tree.disarm();
                return Err(error);
            }
            Ok(tree)
        }
    }

    fn resume_suspended_process(process_id: u32) -> Result<(), String> {
        use std::mem::{size_of, zeroed};

        const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
        const THREAD_SUSPEND_RESUME: u32 = 0x0002;
        let invalid_handle = -1isize as *mut std::ffi::c_void;
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == invalid_handle {
                return Err("The suspended maintenance process could not be inspected.".into());
            }
            let mut entry: ThreadEntry32 = zeroed();
            entry.dwSize = size_of::<ThreadEntry32>() as u32;
            let mut present = Thread32First(snapshot, &mut entry) != 0;
            while present {
                if entry.th32OwnerProcessID == process_id {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if thread.is_null() {
                        CloseHandle(snapshot);
                        return Err(
                            "The suspended maintenance process could not be resumed.".into()
                        );
                    }
                    let previous_count = ResumeThread(thread);
                    CloseHandle(thread);
                    CloseHandle(snapshot);
                    return if previous_count == 1 {
                        Ok(())
                    } else {
                        Err("The suspended maintenance process could not be resumed safely.".into())
                    };
                }
                present = Thread32Next(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
        }
        Err("The suspended maintenance process could not be found.".into())
    }

    fn active_processes(&self) -> Result<u32, String> {
        use std::mem::{size_of, zeroed};
        use std::ptr;

        const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION: i32 = 1;
        let mut information: JobObjectBasicAccountingInformation = unsafe { zeroed() };
        let ok = unsafe {
            QueryInformationJobObject(
                self.job as *mut _,
                JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                &mut information as *mut _ as *mut _,
                size_of::<JobObjectBasicAccountingInformation>() as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err("The maintenance process tree state could not be verified.".into())
        } else {
            Ok(information.ActiveProcesses)
        }
    }

    fn terminate(&self) -> Result<(), String> {
        if unsafe { TerminateJobObject(self.job as *mut _, 1) } == 0 {
            Err("The maintenance process tree could not be stopped.".into())
        } else {
            Ok(())
        }
    }

    fn disarm(&mut self) {
        if self.armed {
            unsafe {
                CloseHandle(self.job as *mut _);
            }
            self.job = 0;
            self.armed = false;
        }
    }
}

#[cfg(windows)]
impl Drop for ProtocolProcessTree {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.terminate();
            self.disarm();
        }
    }
}

#[cfg(windows)]
fn version_endpoints(app: &tauri::AppHandle, version: &str) -> Result<Vec<tauri::Url>, String> {
    if version.is_empty() || !version.chars().all(|ch| ch.is_ascii_digit() || ch == '.') {
        return Err("The installed version has no immutable release manifest.".into());
    }
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|v| v.get("endpoints"))
        .and_then(|v| v.as_array())
        .ok_or("The update channel is unavailable.".to_string())?
        .iter()
        .map(|value| {
            let base = tauri::Url::parse(
                value
                    .as_str()
                    .ok_or("The release address is unavailable.")?,
            )
            .map_err(|e| e.to_string())?;
            base.join(&format!("versions/{version}.json"))
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn launch_operation(
    app: &tauri::AppHandle,
    prepared: &serde_json::Value,
    authorization: &str,
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let helper = prepared["helper"]
        .as_str()
        .ok_or("The retained recovery helper is unavailable.")?;
    let mut command = Command::new(helper);
    command
        .args(["installation-maintenance", "execute"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(&serde_json::to_vec(&serde_json::json!({"authorization": authorization, "parent_pid": std::process::id()})).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    }
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub fn rollback_desktop_update(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    authorization: Option<String>,
    confirm: bool,
) -> Result<(), String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    if !confirm {
        return Err("Review and confirm the completed-upgrade rollback first.".into());
    }
    let authorization = reviewed_authorization(&state, authorization)?;
    let runtime = maintenance_runtime_path()?;
    let details = protocol(
        &runtime,
        "inspect",
        &serde_json::json!({"authorization": authorization}),
    )?;
    if details["operation"] != "rollback" {
        return Err("Use the rollback authorization from Workspace recovery.".into());
    }
    app.state::<lightwork_desktop_runtime::Dashboard>()
        .pause_for_maintenance()?;
    let prepared = protocol(
        &runtime,
        "prepare",
        &serde_json::json!({"authorization": authorization}),
    )?;
    launch_operation(&app, &prepared, &authorization)
}

#[tauri::command]
pub fn resume_desktop_maintenance(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Maintenance>,
    id: String,
    confirm: bool,
) -> Result<(), String> {
    local_controls(&window)?;
    let _busy = acquire(&state)?;
    if !confirm {
        return Err("Review and confirm resuming the unfinished operation first.".into());
    }
    let (runtime, _) = selected_maintenance_runtime()?;
    app.state::<lightwork_desktop_runtime::Dashboard>()
        .pause_for_maintenance()?;
    let prepared = protocol(&runtime, "resume", &serde_json::json!({"id": id}))?;
    let authorization = prepared["authorization"]
        .as_str()
        .ok_or("The recovery authorization is unavailable.")?;
    launch_operation(&app, &prepared, authorization)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_does_not_overlap_checks_or_installation() {
        let state = Maintenance::default();
        let first = acquire(&state).unwrap();
        assert!(acquire(&state).is_err());
        drop(first);
        assert!(acquire(&state).is_ok());
    }

    #[test]
    fn repair_metadata_requires_exact_current_release_hashes_and_no_transition() {
        let raw = serde_json::json!({
            "runtime_sha256": "a".repeat(64),
            "installer_sha256": "b".repeat(64),
        });
        let value =
            repair_download_metadata(&raw, "1.2.3", "signed-envelope", "installed-key").unwrap();
        assert_eq!(value["new"]["runtime_sha256"], "a".repeat(64));
        assert_eq!(value["new"]["installer_sha256"], "b".repeat(64));
        assert_eq!(value["identity_transition"], serde_json::Value::Null);
        assert_eq!(
            repair_authorization_request(&value).unwrap(),
            serde_json::json!({
                "confirm": true,
                "version": "1.2.3",
                "runtime_sha256": "a".repeat(64),
                "installer_sha256": "b".repeat(64),
                "public_key": "installed-key",
            })
        );

        for changed in [
            serde_json::json!({"installer_sha256": "b".repeat(64)}),
            serde_json::json!({"runtime_sha256": "A".repeat(64), "installer_sha256": "b".repeat(64)}),
            serde_json::json!({"runtime_sha256": "a".repeat(64), "installer_sha256": "bad"}),
            serde_json::json!({"runtime_sha256": "a".repeat(64), "installer_sha256": "b".repeat(64), "identity_transition": {}}),
        ] {
            assert!(repair_download_metadata(
                &changed,
                "1.2.3",
                "signed-envelope",
                "installed-key",
            )
            .is_err());
        }
        for changed in [
            serde_json::json!({"new": value["new"]}),
            serde_json::json!({"public_key": "installed-key", "new": {"runtime_sha256": "bad", "installer_sha256": "b".repeat(64)}}),
        ] {
            assert!(repair_authorization_request(&changed).is_err());
        }
    }

    #[test]
    fn every_native_shell_uses_the_physical_recovery_runtime() {
        let directory = std::path::Path::new(r"C:\Program Files\Lightwork");
        for shell in ["maverick-desktop.exe", "maverick-recovery-desktop.exe"] {
            assert_eq!(
                recovery_runtime_for(&directory.join(shell)).unwrap(),
                directory.join("maverick-recovery.exe")
            );
            assert_eq!(
                primary_runtime_for(&directory.join(shell)).unwrap(),
                directory.join("maverick.exe")
            );
        }
    }

    #[test]
    fn maintenance_runtime_selection_prefers_the_retained_helper() {
        let directory = std::path::Path::new(r"C:\Program Files\Lightwork");
        let executable = directory.join("maverick-desktop.exe");
        let mut observed = Vec::new();
        let (selected, status) = select_maintenance_runtime_with(&executable, |candidate| {
            observed.push(candidate.to_path_buf());
            Ok(serde_json::json!({
                "maintenance_protocol": 2,
                "recovery_points": [],
                "incomplete": false,
            }))
        })
        .unwrap();
        assert_eq!(selected, directory.join("maverick-recovery.exe"));
        assert_eq!(observed, vec![directory.join("maverick-recovery.exe")]);
        assert_eq!(status["incomplete"], false);
    }

    #[test]
    fn maintenance_runtime_selection_falls_back_to_the_sibling_primary() {
        let directory = std::path::Path::new(r"C:\Program Files\Lightwork");
        let executable = directory.join("maverick-recovery-desktop.exe");
        let mut observed = Vec::new();
        let (selected, _) = select_maintenance_runtime_with(&executable, |candidate| {
            observed.push(candidate.to_path_buf());
            if candidate.ends_with("maverick-recovery.exe") {
                Err("synthetic retained helper failure".into())
            } else {
                Ok(serde_json::json!({
                    "maintenance_protocol": 2,
                    "recovery_points": [],
                    "incomplete": true,
                }))
            }
        })
        .unwrap();
        assert_eq!(selected, directory.join("maverick.exe"));
        assert_eq!(
            observed,
            vec![
                directory.join("maverick-recovery.exe"),
                directory.join("maverick.exe")
            ]
        );
    }

    #[test]
    fn maintenance_runtime_selection_refuses_when_no_packaged_helper_responds() {
        let executable = std::path::Path::new(r"C:\Program Files\Lightwork\maverick-desktop.exe");
        let error = select_maintenance_runtime_with(&executable, |candidate| {
            if candidate.ends_with("maverick-recovery.exe") {
                Ok(serde_json::json!({"maintenance_protocol": 2, "incomplete": false}))
            } else {
                Err("synthetic primary helper failure".into())
            }
        })
        .expect_err("invalid retained status and failed primary must refuse");
        assert!(error.contains("retained maintenance runtime returned an incomplete status"));
        assert!(error.contains("primary maintenance runtime could not start"));
    }

    fn repair_request_fixture() -> serde_json::Value {
        serde_json::json!({
            "confirm": true,
            "version": "1.2.3",
            "runtime_sha256": "a".repeat(64),
            "installer_sha256": "b".repeat(64),
            "public_key": "installed-key",
        })
    }

    fn repair_capability_fixture(role: &str, retained_installer: bool) -> serde_json::Value {
        serde_json::json!({
            "schema": "lightwork.installation-repair-capability.v1",
            "compatible": true,
            "version": "1.2.3",
            "runtime_sha256": "a".repeat(64),
            "installer_sha256": "b".repeat(64),
            "public_key": "installed-key",
            "runtime_role": role,
            "product_code": "{11111111-2222-3333-4444-555555555555}",
            "package_code": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "retained_installer_available": retained_installer,
        })
    }

    #[test]
    fn repair_runtime_selection_falls_back_from_a_stale_status_only_helper() {
        let directory = std::path::Path::new(r"C:\Program Files\Lightwork");
        let executable = directory.join("maverick-desktop.exe");
        let request = repair_request_fixture();
        let mut observed = Vec::new();
        let (selected, capability) =
            select_repair_runtime_with(&executable, &request, |candidate, _| {
                observed.push(candidate.to_path_buf());
                if candidate.ends_with("maverick-recovery.exe") {
                    Ok(serde_json::json!({
                        "maintenance_protocol": 1,
                        "recovery_points": [],
                        "incomplete": false,
                    }))
                } else {
                    Ok(repair_capability_fixture("primary", false))
                }
            })
            .unwrap();
        assert_eq!(selected, directory.join("maverick.exe"));
        assert_eq!(capability["retained_installer_available"], false);
        assert_eq!(observed.len(), 2);
    }

    #[test]
    fn repair_runtime_selection_requires_exact_identity_and_registered_package() {
        let executable = std::path::Path::new(r"C:\Program Files\Lightwork\maverick-desktop.exe");
        let request = repair_request_fixture();
        let error = select_repair_runtime_with(&executable, &request, |candidate, _| {
            let role = if candidate.ends_with("maverick-recovery.exe") {
                "recovery"
            } else {
                "primary"
            };
            let mut capability = repair_capability_fixture(role, true);
            capability["runtime_sha256"] = serde_json::json!("f".repeat(64));
            capability["product_code"] = serde_json::json!("not-a-product-code");
            Ok(capability)
        })
        .expect_err("a mismatched capability must never select a process endpoint");
        assert!(error.contains("does not match this signed repair release"));
    }

    #[test]
    fn repair_runtime_selection_rejects_absent_identity_on_both_sides() {
        let executable = std::path::Path::new(r"C:\Program Files\Lightwork\maverick-desktop.exe");
        let mut request = repair_request_fixture();
        request
            .as_object_mut()
            .expect("request object")
            .remove("runtime_sha256");
        let error = select_repair_runtime_with(&executable, &request, |candidate, _| {
            let role = if candidate.ends_with("maverick-recovery.exe") {
                "recovery"
            } else {
                "primary"
            };
            let mut capability = repair_capability_fixture(role, true);
            capability
                .as_object_mut()
                .expect("capability object")
                .remove("runtime_sha256");
            Ok(capability)
        })
        .expect_err("missing identity fields must never match as null values");
        assert!(error.contains("does not match this signed repair release"));
    }

    #[test]
    fn maintenance_protocol_steps_have_finite_operation_specific_timeouts() {
        assert_eq!(
            protocol_timeout("authorize-repair"),
            std::time::Duration::from_secs(6 * 60)
        );
        assert_eq!(
            protocol_timeout("repair-capability"),
            std::time::Duration::from_secs(6 * 60)
        );
        assert_eq!(
            protocol_timeout("prepare"),
            std::time::Duration::from_secs(60 * 60)
        );
        for step in ["status", "inspect", "resume", "logs", "unknown"] {
            assert_eq!(protocol_timeout(step), std::time::Duration::from_secs(60));
        }
    }

    #[cfg(windows)]
    #[test]
    fn timed_out_protocol_terminates_its_descendant_tree() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        const ROLE: &str = "LIGHTWORK_MAINTENANCE_TIMEOUT_TEST_ROLE";
        const READY: &str = "LIGHTWORK_MAINTENANCE_TIMEOUT_TEST_READY";
        const TEST: &str = "updates::tests::timed_out_protocol_terminates_its_descendant_tree";
        let executable = std::env::current_exe().expect("test executable");
        // Re-enter this exact native test as the fixture processes. Cold
        // PowerShell startup can consume the entire timeout on a CI runner,
        // leaving the old test with no descendant whose containment it proved.
        match std::env::var(ROLE).as_deref() {
            Ok("descendant") => {
                std::fs::write(
                    std::env::var_os(READY).expect("ready path"),
                    std::process::id().to_string(),
                )
                .expect("announce running descendant");
                std::thread::sleep(Duration::from_secs(120));
                return;
            }
            Ok("parent") => {
                let mut descendant = Command::new(&executable)
                    .args(["--exact", TEST, "--nocapture"])
                    .env(ROLE, "descendant")
                    .stdin(Stdio::null())
                    .creation_flags(0x0800_0000)
                    .spawn()
                    .expect("start native descendant");
                descendant.wait().expect("wait for native descendant");
                return;
            }
            Ok(other) => panic!("unknown timeout fixture role: {other}"),
            Err(_) => {}
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "lightwork-maintenance-timeout-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create timeout fixture");
        let ready = directory.join("ready.txt");
        let mut command = Command::new(&executable);
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(ROLE, "parent")
            .env(READY, &ready);
        let started = Instant::now();
        let error = run_protocol_command(command, b"{}", Duration::from_secs(10))
            .expect_err("hung tree must time out");
        assert!(error.contains("time limit and was stopped"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(20));
        assert!(
            ready.is_file(),
            "the descendant must start before the timeout"
        );
        let descendant_id: u32 = std::fs::read_to_string(&ready)
            .expect("read descendant id")
            .parse()
            .expect("parse descendant id");
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> *mut std::ffi::c_void;
            fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
        }
        // TerminateJobObject is asynchronous. Accept either an already-reaped
        // process or a signalled process handle within the bounded drain time.
        unsafe {
            let process = OpenProcess(0x0010_0000, 0, descendant_id); // SYNCHRONIZE
            if process.is_null() {
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(87));
            } else {
                let waited = WaitForSingleObject(process, 5_000);
                CloseHandle(process);
                assert_eq!(
                    waited, 0,
                    "the timed-out descendant escaped the maintenance Job Object"
                );
            }
        }
        std::fs::remove_dir_all(directory).expect("remove timeout fixture");
    }
}
