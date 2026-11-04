fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "retry_dashboard",
            "dashboard_diagnostics",
            "dashboard_readiness",
            "startup_support_report",
            "switch_recovery_mode",
            "maintenance_status",
            "review_maintenance_handoff",
            "desktop_recovery_plan",
            "review_offline_repair",
            "install_offline_repair",
            "check_desktop_update",
            "install_desktop_update",
            "rollback_desktop_update",
            "resume_desktop_maintenance",
            "desktop_maintenance_logs",
            "prepare_oauth_return",
            "launch_oauth_return",
            "consume_oauth_return",
            "cancel_oauth_return",
        ]),
    ))
    .expect("desktop permission manifest");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Tauri embeds resources for the application binary; the lib unit-test
        // harness also imports TaskDialogIndirect and needs Common Controls v6.
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"); // pragma: allowlist secret -- Microsoft's public assembly identity

        // The application already has Tauri's full manifest in resource.lib.
        // Disable linker synthesis for that binary so both manifests cannot
        // collide; its existing embedded declarations remain intact.
        println!("cargo:rustc-link-arg-bin=maverick-desktop=/MANIFEST:NO");
    }
}
