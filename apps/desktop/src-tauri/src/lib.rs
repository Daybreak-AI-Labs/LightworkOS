//! Tauri shell for the local Lightwork dashboard.
//!
//! The window first shows a bundled splash page (ui/index.html + ui/app.js)
//! that polls `http://127.0.0.1:8765/healthz` (an auth-exempt endpoint, see
//! maverick_dashboard/app.py `_AUTH_EXEMPT`) and navigates to the dashboard as
//! soon as the port answers. On the Rust side, if nothing is listening on
//! 127.0.0.1:8765 at launch we spawn the user's installed CLI —
//! `maverick dashboard --host 127.0.0.1 --port 8765` — as a child process and
//! drain it on exit, with bounded forced termination if it cannot finish.
//! A dashboard the user already runs is left untouched.
//!
//! Customer builds carry the full frozen release runtime beside this binary.
//! Engineering builds retain the installed-CLI lookup for local development.

mod native_oauth;
mod updates;

use lightwork_desktop_runtime::{Dashboard, DASHBOARD_URL};
use std::process::Command;

use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder};
use tauri::{Manager, RunEvent};

#[tauri::command]
async fn retry_dashboard(app: tauri::AppHandle) -> Result<String, String> {
    // The readiness check can take about two seconds on Windows; keep it off
    // the main thread so the window stays responsive.
    tauri::async_runtime::spawn_blocking(move || app.state::<Dashboard>().start())
        .await
        .map_err(|_| "The startup check could not complete.".to_string())?
}

/// Start (or confirm) the dashboard without holding up the window.
fn start_in_background<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let app = app.clone();
    std::thread::spawn(move || {
        let _ = app.state::<Dashboard>().start();
    });
}

#[tauri::command]
fn dashboard_diagnostics(state: tauri::State<'_, Dashboard>) -> Result<String, String> {
    state.diagnostics()
}

#[tauri::command]
async fn dashboard_readiness(window: tauri::WebviewWindow) -> Result<serde_json::Value, String> {
    let url = window
        .url()
        .map_err(|_| "The startup window is unavailable.")?;
    if url != bundled_splash_url()
        && url != bundled_root_url()
        && url != bundled_page_url("")
        && url != bundled_page_url("recovery.html")
    {
        return Err("Open the native startup or recovery page to check readiness.".into());
    }
    let result =
        tauri::async_runtime::spawn_blocking(lightwork_desktop_runtime::dashboard_readiness)
            .await
            .map_err(|_| "The readiness check could not complete.")?;
    use lightwork_desktop_runtime::Readiness;
    let (service, state) = match result {
        Readiness::Ready => ("lightwork-dashboard", "ready"),
        Readiness::SetupRequired => ("lightwork-dashboard", "setup_required"),
        Readiness::NotRunning => ("", "not_running"),
        Readiness::Conflict => ("", "conflict"),
        Readiness::Unavailable => ("", "unavailable"),
    };
    Ok(serde_json::json!({"service": service, "state": state}))
}

#[tauri::command]
fn startup_support_report(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Dashboard>,
) -> Result<serde_json::Value, String> {
    startup_report_for_url(
        &window
            .url()
            .map_err(|_| "The startup window is unavailable.")?,
        &state,
    )
}

fn startup_report_for_url(
    url: &tauri::Url,
    state: &Dashboard,
) -> Result<serde_json::Value, String> {
    // Tauri maps the default App(index.html) window to the bundled root;
    // reconnect navigates to the explicit index.html URL. Admit only those
    // exact pages (including the custom scheme's empty/slash root forms),
    // with no query, fragment, credentials or alternate port.
    if *url != bundled_splash_url() && *url != bundled_root_url() && *url != bundled_page_url("") {
        return Err("Open the app's startup screen to prepare startup diagnostics.".into());
    }
    let facts = state.startup_support()?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "The system clock is unavailable.")?
        .as_millis();
    Ok(serde_json::json!({
        "schema": "lightwork.startup-support.v1",
        "correlation_id": format!("startup-{timestamp:x}"),
        "generated_at_unix_ms": timestamp,
        "desktop_version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "packaged_runtime_available": facts.packaged_runtime_available,
        "process_state": facts.process_state,
        "recovery_mode": facts.recovery_mode,
        "scope": "Startup facts only. Configuration, account data, paths and startup logs are excluded. Full diagnostics are available from Help after sign-in."
    }))
}

#[tauri::command]
fn switch_recovery_mode(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Dashboard>,
    recovery: bool,
    confirm: bool,
) -> Result<String, String> {
    if window
        .url()
        .map_err(|_| "The recovery window is unavailable.")?
        != bundled_page_url("recovery.html")
        || !confirm
    {
        return Err("Review and confirm this action in the app's recovery controls.".into());
    }
    state.switch_recovery_mode(recovery)
}

fn bundled_page_url(page: &str) -> tauri::Url {
    // Tauri's bundled-asset origin, matching the default useHttpsScheme=false
    // in tauri.conf.json. This destination never comes from dashboard content.
    let origin = if cfg!(windows) {
        "http://tauri.localhost/"
    } else {
        "tauri://localhost/"
    };
    format!("{origin}{page}")
        .parse()
        .expect("fixed bundled page address")
}

fn bundled_splash_url() -> tauri::Url {
    bundled_page_url("index.html")
}

fn bundled_root_url() -> tauri::Url {
    let mut url = bundled_splash_url();
    // Special HTTP URLs retain '/', while Tauri's custom scheme uses no path.
    url.set_path("");
    url
}

fn reconnect_dashboard<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    start: impl FnOnce(),
) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main") {
        // Return to local recovery controls even if launch fails. Remote
        // dashboard pages retain no authority to invoke native commands.
        window.navigate(bundled_splash_url())?;
        start();
    }
    Ok(())
}

/// Open a URL in the user's default browser (std only — no extra plugin/dep).
fn open_in_browser(url: &str) {
    let spawn = |program: &str, args: &[&str]| {
        let _ = Command::new(program).args(args).spawn();
    };
    #[cfg(target_os = "macos")]
    spawn("open", &[url]);
    #[cfg(target_os = "windows")]
    spawn("cmd", &["/C", "start", "", url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    spawn("xdg-open", &[url]);
}

pub fn run() {
    let context = tauri::generate_context!();
    if std::env::args().nth(1).as_deref() == Some("--maintenance-channel") {
        // A fixed machine-readable query used by the installed frozen runtime
        // to bind an authenticated maintenance grant to this compiled channel.
        let key = context
            .config()
            .plugins
            .0
            .get("updater")
            .and_then(|value| value.get("pubkey"));
        println!(
            "{}",
            serde_json::json!({"public_key": key, "version": context.package_info().version.to_string(),
            "packaged_runtime": cfg!(all(windows, feature = "customer-runtime"))})
        );
        return;
    }
    // Generate a per-shell key in memory. Pass it directly to the dashboard
    // child instead of placing it in this process's environment, where an OS
    // opener or unrelated child could inherit it.
    let (oauth_broker, dashboard_ticket_key) =
        lightwork_desktop_oauth_return::Broker::for_dashboard_process()
            .expect("secure desktop account-return authority");
    std::env::remove_var(lightwork_desktop_oauth_return::TICKET_KEY_ENV);
    #[cfg(feature = "customer-runtime")]
    let dashboard = Dashboard::with_binary_and_environment(
        std::env::current_exe()
            .expect("installed executable path")
            .parent()
            .expect("installed executable directory")
            .join("maverick.exe"),
        lightwork_desktop_oauth_return::TICKET_KEY_ENV,
        dashboard_ticket_key,
    );
    #[cfg(not(feature = "customer-runtime"))]
    let dashboard = Dashboard::with_environment(
        lightwork_desktop_oauth_return::TICKET_KEY_ENV,
        dashboard_ticket_key,
    );
    // The secret exists only in broker memory and the dashboard-child process tree.
    // A different listener already occupying the dashboard port cannot mint a
    // native OAuth ticket accepted by this broker.
    let maintenance_result = std::env::args().any(|argument| argument == "--maintenance-result");

    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    builder
        .manage(dashboard)
        .manage(updates::Maintenance::default())
        .manage(oauth_broker)
        .invoke_handler(tauri::generate_handler![
            retry_dashboard,
            dashboard_diagnostics,
            dashboard_readiness,
            startup_support_report,
            switch_recovery_mode,
            native_oauth::prepare_oauth_return,
            native_oauth::launch_oauth_return,
            native_oauth::consume_oauth_return,
            native_oauth::cancel_oauth_return,
            updates::maintenance_status,
            updates::review_maintenance_handoff,
            updates::desktop_recovery_plan,
            updates::review_offline_repair,
            updates::install_offline_repair,
            updates::check_desktop_update,
            updates::install_desktop_update,
            updates::rollback_desktop_update,
            updates::resume_desktop_maintenance,
            updates::desktop_maintenance_logs
        ])
        .on_page_load(|webview, payload| {
            if webview.label() == "main"
                && matches!(payload.event(), tauri::webview::PageLoadEvent::Started)
            {
                webview
                    .state::<lightwork_desktop_oauth_return::Broker>()
                    .stop();
            }
        })
        .setup(move |app| {
            if maintenance_result {
                if let Some(window) = app.get_webview_window("main") {
                    window.navigate(bundled_page_url("maintenance.html"))?;
                }
            } else {
                // The splash polls readiness itself, so the window need not
                // wait for this check (about two seconds on Windows).
                start_in_background(app.handle());
            }
            Ok(())
        })
        // A real menu: Reload / Open in Browser / Quit, plus a standard Edit
        // menu so Cmd-C / Cmd-V / Select-All work in the dashboard's text
        // fields (on macOS the webview has no clipboard shortcuts without it).
        .menu(|handle| {
            let open_browser = MenuItemBuilder::with_id("open_browser", "Open in Browser")
                .accelerator("CmdOrCtrl+Shift+O")
                .build(handle)?;
            let reload = MenuItemBuilder::with_id("reload", "Reload Dashboard")
                .accelerator("CmdOrCtrl+R")
                .build(handle)?;
            let reconnect =
                MenuItemBuilder::with_id("reconnect", "Reconnect Lightwork").build(handle)?;
            let maintenance =
                MenuItemBuilder::with_id("maintenance", "Install & updates").build(handle)?;
            let recovery =
                MenuItemBuilder::with_id("recovery", "Workspace recovery mode").build(handle)?;
            let quit = PredefinedMenuItem::quit(handle, Some("Quit Lightwork"))?;
            let app_menu = SubmenuBuilder::new(handle, "Lightwork")
                .item(&open_browser)
                .item(&reload)
                .item(&reconnect)
                .item(&maintenance)
                .item(&recovery)
                .separator()
                .item(&quit)
                .build()?;
            let edit = SubmenuBuilder::new(handle, "Edit")
                .undo()
                .redo()
                .separator()
                .cut()
                .copy()
                .paste()
                .select_all()
                .build()?;
            MenuBuilder::new(handle).item(&app_menu).item(&edit).build()
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "reload" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.eval("window.location.reload()");
                }
            }
            "open_browser" => open_in_browser(DASHBOARD_URL),
            "maintenance" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.navigate(bundled_page_url("maintenance.html"));
                }
            }
            "recovery" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.navigate(bundled_page_url("recovery.html"));
                }
            }
            "reconnect" => {
                let _ = reconnect_dashboard(app, || start_in_background(app));
            }
            _ => {}
        })
        .build(context)
        .expect("error while building the Lightwork desktop shell")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                app.state::<lightwork_desktop_oauth_return::Broker>().stop();
                // Drain only our owned child, then use the finite force-stop
                // fallback. An external dashboard is never in owned state.
                app.state::<Dashboard>().stop_owned();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_report_is_allowlisted_and_available_only_from_bundled_splash() {
        let dashboard = Dashboard::default();
        for url in [
            bundled_root_url(),
            bundled_page_url(""),
            bundled_splash_url(),
        ] {
            let report = startup_report_for_url(&url, &dashboard).unwrap();
            assert_eq!(report["schema"], "lightwork.startup-support.v1");
            assert_eq!(report["process_state"], "not_started");
            assert_eq!(report.as_object().unwrap().len(), 9);
        }
        for url in [
            DASHBOARD_URL.parse().unwrap(),
            "https://example.test/".parse().unwrap(),
            "http://tauri.localhost.example.test/".parse().unwrap(),
            "http://tauri.localhost:8765/".parse().unwrap(),
            "http://user@tauri.localhost/".parse().unwrap(),
            bundled_page_url("maintenance.html"),
            bundled_page_url("recovery.html"),
            bundled_page_url("?private-query"),
            bundled_page_url("#private-fragment"),
            bundled_page_url("index.html?private-query"),
            bundled_page_url("index.html#private-fragment"),
        ] {
            assert!(startup_report_for_url(&url, &dashboard).is_err());
        }
    }

    #[test]
    fn startup_report_accepts_the_framework_resolved_default_window_url() {
        // Read the real window configuration and let pinned Tauri resolve its
        // omitted URL. The framework maps App(index.html) to the origin root.
        let config: tauri::utils::config::Config =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let app = tauri::test::mock_app();
        let window = tauri::WebviewWindowBuilder::from_config(&app, &config.app.windows[0])
            .unwrap()
            .build()
            .unwrap();
        let actual = window.url().unwrap();
        assert_eq!(actual, bundled_root_url());
        assert!(startup_report_for_url(&actual, &Dashboard::default()).is_ok());
    }

    #[test]
    fn reconnect_returns_a_failed_dashboard_to_bundled_controls_before_launch() {
        let app = tauri::test::mock_app();
        let window = tauri::WebviewWindowBuilder::new(
            &app,
            "main",
            tauri::WebviewUrl::External(DASHBOARD_URL.parse().unwrap()),
        )
        .build()
        .unwrap();
        let mut starts = 0;
        reconnect_dashboard(app.handle(), || {
            assert_eq!(window.url().unwrap(), bundled_splash_url());
            starts += 1;
        })
        .unwrap();
        assert_eq!(starts, 1);
        assert_ne!(window.url().unwrap().as_str(), DASHBOARD_URL);
    }

    #[test]
    fn reconnect_does_not_launch_without_a_recovery_window() {
        let app = tauri::test::mock_app();
        reconnect_dashboard(app.handle(), || panic!("no window to recover")).unwrap();
    }
}
