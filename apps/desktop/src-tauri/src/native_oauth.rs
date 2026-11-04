//! Narrow command adapters; all URL/caller/state checks live in the tested broker.
use lightwork_desktop_oauth_return::{Broker, Outcome, CALLBACK, PROFILE};

fn caller(window: &tauri::WebviewWindow) -> Result<String, String> {
    window
        .url()
        .map(|url| url.to_string())
        .map_err(|_| "Connections is unavailable.".into())
}

#[tauri::command]
pub fn prepare_oauth_return(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Broker>,
    context: String,
    ticket: String,
) -> Result<serde_json::Value, String> {
    let handle = broker.prepare(window.label(), &caller(&window)?, &context, &ticket)?;
    Ok(
        serde_json::json!({"handle": handle, "context": context, "return_profile": PROFILE, "callback_uri": CALLBACK, "expires_in": 600}),
    )
}

#[tauri::command]
pub fn launch_oauth_return(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Broker>,
    handle: String,
    context: String,
    authorize_url: String,
    state: String,
    ticket: String,
) -> Result<(), String> {
    broker
        .launch(
            window.label(),
            &caller(&window)?,
            &handle,
            &context,
            &authorize_url,
            &state,
            &ticket,
            open_provider,
        )
        .map_err(Into::into)
}

#[tauri::command]
pub fn consume_oauth_return(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Broker>,
    handle: String,
    context: String,
    ticket: String,
) -> Result<serde_json::Value, String> {
    let result = broker.consume(
        window.label(),
        &caller(&window)?,
        &handle,
        &context,
        &ticket,
    )?;
    // Return sensitive bytes only to the exact originating page/attempt/context,
    // never via a broadcast event, log, diagnostic string, or navigated URL.
    Ok(match result {
        Outcome::Pending => serde_json::json!({"outcome": "pending", "context": context}),
        Outcome::Returned { state, code } => {
            serde_json::json!({"outcome": "returned", "state": state, "code": code, "context": context})
        }
        Outcome::Denied => serde_json::json!({"outcome": "denied", "context": context}),
        Outcome::Expired => serde_json::json!({"outcome": "expired", "context": context}),
        Outcome::Unavailable => serde_json::json!({"outcome": "unavailable", "context": context}),
    })
}

#[tauri::command]
pub fn cancel_oauth_return(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Broker>,
    handle: String,
    context: String,
    ticket: String,
) -> Result<(), String> {
    broker
        .cancel(
            window.label(),
            &caller(&window)?,
            &handle,
            &context,
            &ticket,
        )
        .map_err(Into::into)
}

fn open_provider(url: &str) -> Result<(), &'static str> {
    // Called only after the broker validates an exact provider endpoint, state,
    // callback and PKCE request. No shell ever interprets the query string.
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                window: *mut std::ffi::c_void,
                operation: *const u16,
                file: *const u16,
                parameters: *const u16,
                directory: *const u16,
                show: i32,
            ) -> isize;
        }
        let operation: Vec<u16> = "open\0".encode_utf16().collect();
        let file: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        };
        if result <= 32 {
            return Err("System browser unavailable.");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let program = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        std::process::Command::new(program)
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|mut child| {
                // Reap the opener without retaining or printing its URL.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            })
            .map_err(|_| "System browser unavailable.")
    }
}
