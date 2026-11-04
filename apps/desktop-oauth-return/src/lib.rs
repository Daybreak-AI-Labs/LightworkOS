//! One bounded, memory-only OAuth callback for the exact signed-in desktop page.
//! Native authority requires a per-shell HMAC ticket issued by its dashboard child.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const CALLBACK: &str = "http://127.0.0.1:8766/connections";
pub const PROFILE: &str = "desktop-loopback-v1";
pub const CALLER: &str = "http://127.0.0.1:8765/connections";
const MAX_REQUEST: usize = 16 * 1024;
const MAX_TICKET: usize = 8192;
const TICKET_SCHEMA: &str = "lightwork.native-oauth-ticket.v1";
pub const TICKET_KEY_ENV: &str = "MAVERICK_DESKTOP_OAUTH_TICKET_KEY";
const PROFILE_SCOPE_CONTRACT: &str = include_str!("../oauth-profile-scopes.tsv");
const REFUSED: &str = "Account return could not be matched. Start sign-in again in Lightwork.";

type Ticket = BTreeMap<String, String>;

pub enum Outcome {
    Pending,
    Returned { state: String, code: String },
    Denied,
    Expired,
    Unavailable,
}

struct Session {
    state: Option<String>,
    deadline: Instant,
    outcome: Option<Outcome>,
}

struct Running {
    handle: String,
    context: String,
    prepare_ticket_sha256: String,
    prepare_jti: String,
    launch_ticket_sha256: Option<String>,
    launch_jti: Option<String>,
    session: Arc<Mutex<Session>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub struct Broker {
    running: Mutex<Option<Running>>,
    key: [u8; 32],
    instance: String,
}

pub fn authorize_caller(label: &str, url: &str) -> Result<(), &'static str> {
    if label != "main" || url != CALLER {
        return Err("Open Connections in the local Lightwork desktop app.");
    }
    Ok(())
}

fn hex_context(value: &str) -> bool {
    hex_digest(value)
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn token(value: &str, low: usize, high: usize) -> bool {
    (low..=high).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn sha256(value: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_length = (value.len() as u64).wrapping_mul(8);
    let mut padded = Vec::new();
    padded.extend_from_slice(value);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());
    let mut state = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(word.try_into().expect("four byte word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let first = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut result = [0_u8; 32];
    for (chunk, value) in result.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    result
}

fn sha256_hex_bytes(value: &[u8]) -> String {
    sha256(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_hex(value: &str) -> String {
    sha256_hex_bytes(value.as_bytes())
}

fn hmac_sha256(key: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(64 + value.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(value);
    let digest = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&digest);
    sha256(&outer)
}

fn unix_time() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| "The system clock is unavailable for account sign-in.")
}

fn decode(value: &str) -> Result<String, &'static str> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(REFUSED);
                }
                let part =
                    std::str::from_utf8(&bytes[index + 1..index + 3]).map_err(|_| REFUSED)?;
                result.push(u8::from_str_radix(part, 16).map_err(|_| REFUSED)?);
                index += 3;
            }
            b'+' => {
                result.push(b' ');
                index += 1;
            }
            byte => {
                result.push(byte);
                index += 1;
            }
        }
    }
    let text = String::from_utf8(result).map_err(|_| REFUSED)?;
    if text.chars().any(char::is_control) {
        return Err(REFUSED);
    }
    Ok(text)
}

fn query(value: &str) -> Result<Ticket, &'static str> {
    let mut result = Ticket::new();
    for part in value.split('&') {
        let (key, value) = part.split_once('=').ok_or(REFUSED)?;
        if result.len() >= 24 {
            return Err(REFUSED);
        }
        if result.insert(decode(key)?, decode(value)?).is_some() {
            return Err(REFUSED);
        }
    }
    Ok(result)
}

fn field<'a>(ticket: &'a Ticket, name: &str) -> Result<&'a str, &'static str> {
    ticket.get(name).map(String::as_str).ok_or(REFUSED)
}

fn number(ticket: &Ticket, name: &str) -> Result<u64, &'static str> {
    let value = field(ticket, name)?;
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(REFUSED);
    }
    value.parse().map_err(|_| REFUSED)
}

fn exact_fields(ticket: &Ticket, expected: &[&str]) -> bool {
    ticket.len() == expected.len() && expected.iter().all(|name| ticket.contains_key(*name))
}

fn ticket_payload(ticket: &str, key: &[u8; 32]) -> Result<Ticket, &'static str> {
    if !(100..=MAX_TICKET).contains(&ticket.len()) || !ticket.is_ascii() {
        return Err(REFUSED);
    }
    let (body, signature) = ticket.split_once('.').ok_or(REFUSED)?;
    if body.contains('.')
        || signature.contains('.')
        || body.len() < 64
        || body.len() > MAX_TICKET - 65
        || body.len() % 2 != 0
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !hex_digest(signature)
    {
        return Err(REFUSED);
    }
    let expected: String = hmac_sha256(key, body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !equal(signature, &expected) {
        return Err(REFUSED);
    }
    let decoded: Vec<u8> = body
        .as_bytes()
        .chunks_exact(2)
        .map(|part| {
            std::str::from_utf8(part)
                .map_err(|_| REFUSED)
                .and_then(|value| u8::from_str_radix(value, 16).map_err(|_| REFUSED))
        })
        .collect::<Result<_, _>>()?;
    if decoded.len() > MAX_TICKET / 2 {
        return Err(REFUSED);
    }
    query(&String::from_utf8(decoded).map_err(|_| REFUSED)?)
}

fn validate_ticket_time(
    ticket: &Ticket,
    purpose: &str,
    instance: &str,
) -> Result<u64, &'static str> {
    let now = unix_time()?;
    let issued_at = number(ticket, "issued_at")?;
    let expires_at = number(ticket, "expires_at")?;
    if field(ticket, "schema")? != TICKET_SCHEMA
        || field(ticket, "purpose")? != purpose
        || !equal(field(ticket, "instance")?, instance)
        || !token(field(ticket, "jti")?, 40, 64)
        || issued_at > now.saturating_add(5)
        || expires_at <= now
        || expires_at > issued_at.saturating_add(600)
    {
        return Err("Desktop account-return authorization expired or could not be verified.");
    }
    Ok(expires_at - now)
}

fn valid_profile(profile: &str, provider: &str, scopes: &str) -> bool {
    PROFILE_SCOPE_CONTRACT.lines().any(|line| {
        let mut fields = line.split('\t');
        fields.next() == Some(profile)
            && fields.next() == Some(provider)
            && fields.next() == Some(scopes)
            && fields.next().is_none()
    })
}

fn validate_bound_fields(ticket: &Ticket) -> Result<(), &'static str> {
    if !hex_digest(field(ticket, "tenant_sha256")?)
        || !hex_digest(field(ticket, "principal_sha256")?)
        || !hex_context(field(ticket, "context")?)
        || !hex_digest(field(ticket, "client_id_sha256")?)
        || field(ticket, "callback_uri")? != CALLBACK
        || !valid_profile(
            field(ticket, "profile")?,
            field(ticket, "provider")?,
            field(ticket, "scopes")?,
        )
        || !hex_digest(field(ticket, "name_sha256")?)
        || !hex_digest(field(ticket, "site_url_sha256")?)
        || !hex_digest(field(ticket, "expected_revision_sha256")?)
    {
        return Err(REFUSED);
    }
    Ok(())
}

fn prepare_ticket(
    ticket: &str,
    key: &[u8; 32],
    instance: &str,
    context: &str,
) -> Result<(Ticket, u64), &'static str> {
    const FIELDS: &[&str] = &[
        "callback_uri",
        "client_id_sha256",
        "context",
        "expected_revision_sha256",
        "expires_at",
        "instance",
        "issued_at",
        "jti",
        "name_sha256",
        "principal_sha256",
        "profile",
        "provider",
        "purpose",
        "schema",
        "scopes",
        "site_url_sha256",
        "tenant_sha256",
    ];
    let value = ticket_payload(ticket, key)?;
    if !exact_fields(&value, FIELDS) {
        return Err(REFUSED);
    }
    let lifetime = validate_ticket_time(&value, "prepare", instance)?;
    validate_bound_fields(&value)?;
    if !equal(field(&value, "context")?, context) {
        return Err(REFUSED);
    }
    Ok((value, lifetime))
}

fn validate_authorization(url: &str, state: &str, ticket: &Ticket) -> Result<(), &'static str> {
    if url.len() > MAX_REQUEST
        || !url.is_ascii()
        || url.contains('#')
        || url.bytes().any(|byte| byte.is_ascii_control())
        || !token(state, 40, 64)
        || sha256_hex(url) != field(ticket, "authorize_url_sha256")?
    {
        return Err(REFUSED);
    }
    let provider = field(ticket, "provider")?;
    let (raw_query, expected_fields): (&str, &[&str]) = match provider {
        "google" => (
            url.strip_prefix("https://accounts.google.com/o/oauth2/v2/auth?")
                .ok_or("This provider sign-in address is not supported.")?,
            &[
                "access_type",
                "client_id",
                "code_challenge",
                "code_challenge_method",
                "prompt",
                "redirect_uri",
                "response_type",
                "scope",
                "state",
            ],
        ),
        "atlassian" => (
            url.strip_prefix("https://auth.atlassian.com/authorize?")
                .ok_or("This provider sign-in address is not supported.")?,
            &[
                "audience",
                "client_id",
                "code_challenge",
                "code_challenge_method",
                "prompt",
                "redirect_uri",
                "response_type",
                "scope",
                "state",
            ],
        ),
        "microsoft" => (
            url.strip_prefix("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?")
                .ok_or("This provider sign-in address is not supported.")?,
            &[
                "client_id", "code_challenge", "code_challenge_method", "nonce",
                "redirect_uri", "response_type", "scope", "state",
            ],
        ),
        _ => return Err(REFUSED),
    };
    let fields = query(raw_query)?;
    let client_hash = field(ticket, "client_id_sha256")?;
    let challenge = field(ticket, "pkce_challenge")?;
    if !exact_fields(&fields, expected_fields)
        || fields.get("state").map(String::as_str) != Some(state)
        || !equal(state, field(ticket, "state")?)
        || sha256_hex(state) != field(ticket, "consent_sha256")?
        || fields.get("redirect_uri").map(String::as_str) != Some(CALLBACK)
        || fields.get("response_type").map(String::as_str) != Some("code")
        || fields.get("client_id").is_none_or(|value| {
            value.is_empty() || value.len() > 1024 || sha256_hex(value) != client_hash
        })
        || fields.get("code_challenge_method").map(String::as_str) != Some("S256")
        || fields
            .get("code_challenge")
            .is_none_or(|value| !token(value, 43, 128) || !equal(value, challenge))
        || fields.get("scope").map(String::as_str) != Some(field(ticket, "scopes")?)
        || match provider {
            "google" => {
                fields.get("access_type").map(String::as_str) != Some("offline")
                    || fields.get("prompt").map(String::as_str) != Some("consent")
            }
            "atlassian" => {
                fields.get("audience").map(String::as_str) != Some("api.atlassian.com")
                    || fields.get("prompt").map(String::as_str) != Some("consent")
            }
            "microsoft" => fields.get("nonce").is_none_or(|value| !token(value, 40, 64)),
            _ => true,
        }
    {
        return Err(REFUSED);
    }
    Ok(())
}

fn launch_ticket(
    ticket: &str,
    key: &[u8; 32],
    instance: &str,
    context: &str,
    handle: &str,
    authorize_url: &str,
    state: &str,
    expected_prepare_sha256: &str,
    expected_prepare_jti: &str,
) -> Result<Ticket, &'static str> {
    const FIELDS: &[&str] = &[
        "authorize_url_sha256",
        "callback_uri",
        "client_id_sha256",
        "consent_sha256",
        "context",
        "expected_revision_sha256",
        "expires_at",
        "instance",
        "issued_at",
        "jti",
        "name_sha256",
        "native_handle_sha256",
        "pkce_challenge",
        "prepare_jti",
        "prepare_ticket_sha256",
        "principal_sha256",
        "profile",
        "provider",
        "purpose",
        "schema",
        "scopes",
        "site_url_sha256",
        "state",
        "tenant_sha256",
    ];
    let value = ticket_payload(ticket, key)?;
    if !exact_fields(&value, FIELDS) {
        return Err(REFUSED);
    }
    validate_ticket_time(&value, "launch", instance)?;
    validate_bound_fields(&value)?;
    if !equal(field(&value, "context")?, context)
        || !hex_digest(field(&value, "consent_sha256")?)
        || !token(field(&value, "state")?, 40, 64)
        || !token(field(&value, "pkce_challenge")?, 43, 128)
        || !hex_digest(field(&value, "authorize_url_sha256")?)
        || !hex_digest(field(&value, "native_handle_sha256")?)
        || !hex_digest(field(&value, "prepare_ticket_sha256")?)
        || !token(field(&value, "prepare_jti")?, 40, 64)
        || equal(field(&value, "jti")?, field(&value, "prepare_jti")?)
        || sha256_hex(handle) != field(&value, "native_handle_sha256")?
        || !equal(
            field(&value, "prepare_ticket_sha256")?,
            expected_prepare_sha256,
        )
        || !equal(field(&value, "prepare_jti")?, expected_prepare_jti)
    {
        return Err(REFUSED);
    }
    validate_authorization(authorize_url, state, &value)?;
    Ok(value)
}

fn random_bytes() -> Result<[u8; 32], &'static str> {
    let mut bytes = [0_u8; 32];
    #[cfg(windows)]
    {
        // Resolve BCryptGenRandom at runtime so this small broker can also be
        // built with Rust's self-contained Windows GNU/LLVM toolchain.  The
        // normal MSVC build still calls the same system implementation, while
        // neither build needs to carry a second random-number generator.
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryW(name: *const u16) -> *mut std::ffi::c_void;
            fn GetProcAddress(
                module: *mut std::ffi::c_void,
                name: *const u8,
            ) -> *mut std::ffi::c_void;
            fn FreeLibrary(module: *mut std::ffi::c_void) -> i32;
        }
        type BCryptGenRandom =
            unsafe extern "system" fn(*mut std::ffi::c_void, *mut u8, u32, u32) -> i32;
        let library: Vec<u16> = "bcrypt.dll\0".encode_utf16().collect();
        let module = unsafe { LoadLibraryW(library.as_ptr()) };
        if module.is_null() {
            return Err("Secure account-return setup is unavailable.");
        }
        let symbol = unsafe { GetProcAddress(module, c"BCryptGenRandom".as_ptr().cast()) };
        if symbol.is_null() {
            unsafe { FreeLibrary(module) };
            return Err("Secure account-return setup is unavailable.");
        }
        let generate: BCryptGenRandom = unsafe { std::mem::transmute(symbol) };
        let status = unsafe { generate(std::ptr::null_mut(), bytes.as_mut_ptr(), 32, 2) };
        unsafe { FreeLibrary(module) };
        if status != 0 {
            return Err("Secure account-return setup is unavailable.");
        }
    }
    #[cfg(not(windows))]
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "Secure account-return setup is unavailable.")?;
    Ok(bytes)
}

fn random_handle() -> Result<String, &'static str> {
    Ok(random_bytes()?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

impl Default for Broker {
    fn default() -> Self {
        Self::with_key(random_bytes().expect("secure account-return key"))
    }
}

impl Broker {
    fn with_key(key: [u8; 32]) -> Self {
        Self {
            running: Mutex::new(None),
            instance: sha256_hex_bytes(&key),
            key,
        }
    }

    /// Create authority and return the value that must be passed only to the
    /// dashboard child. The desktop process environment is never modified.
    pub fn for_dashboard_process() -> Result<(Self, String), &'static str> {
        let key = random_bytes()?;
        let dashboard_key = key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok((Self::with_key(key), dashboard_key))
    }

    pub fn prepare(
        &self,
        label: &str,
        caller: &str,
        context: &str,
        ticket: &str,
    ) -> Result<String, &'static str> {
        authorize_caller(label, caller)?;
        if !hex_context(context) {
            return Err(REFUSED);
        }
        let (prepared, lifetime) = prepare_ticket(ticket, &self.key, &self.instance, context)?;
        self.prepare_on(
            context,
            ticket,
            field(&prepared, "jti")?,
            "127.0.0.1:8766",
            Duration::from_secs(lifetime),
        )
    }

    fn prepare_on(
        &self,
        context: &str,
        ticket: &str,
        prepare_jti: &str,
        address: &str,
        lifetime: Duration,
    ) -> Result<String, &'static str> {
        let mut slot = self.running.lock().map_err(|_| REFUSED)?;
        let expired = slot.as_ref().is_some_and(|current| {
            current
                .session
                .lock()
                .map(|session| Instant::now() >= session.deadline)
                .unwrap_or(true)
        });
        if expired {
            drop(slot.take());
        }
        if slot.is_some() {
            return Err("Another account sign-in is pending. Cancel it before starting again.");
        }
        let listener = TcpListener::bind(address).map_err(|_| {
            "The registered account-return port is busy. Close the other sign-in attempt and retry."
        })?;
        listener.set_nonblocking(true).map_err(|_| REFUSED)?;
        let host = listener.local_addr().map_err(|_| REFUSED)?.to_string();
        let session = Arc::new(Mutex::new(Session {
            state: None,
            deadline: Instant::now() + lifetime,
            outcome: None,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = random_handle()?;
        let thread_session = Arc::clone(&session);
        let thread_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("account-return".into())
            .spawn(move || receive(listener, host, thread_session, thread_stop))
            .map_err(|_| "Account-return receiver could not start.")?;
        *slot = Some(Running {
            handle: handle.clone(),
            context: context.into(),
            prepare_ticket_sha256: sha256_hex(ticket),
            prepare_jti: prepare_jti.into(),
            launch_ticket_sha256: None,
            launch_jti: None,
            session,
            stop,
            worker: Some(worker),
        });
        Ok(handle)
    }

    pub fn launch(
        &self,
        label: &str,
        caller: &str,
        handle: &str,
        context: &str,
        url: &str,
        state: &str,
        ticket: &str,
        open: impl FnOnce(&str) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        authorize_caller(label, caller)?;
        let mut slot = self.running.lock().map_err(|_| REFUSED)?;
        let current = slot.as_mut().ok_or(REFUSED)?;
        if !equal(handle, &current.handle) || !equal(context, &current.context) {
            return Err(REFUSED);
        }
        let launched = launch_ticket(
            ticket,
            &self.key,
            &self.instance,
            context,
            handle,
            url,
            state,
            &current.prepare_ticket_sha256,
            &current.prepare_jti,
        )?;
        let mut session = current.session.lock().map_err(|_| REFUSED)?;
        if Instant::now() >= session.deadline
            || session.state.is_some()
            || session.outcome.is_some()
            || current.launch_ticket_sha256.is_some()
        {
            return Err(REFUSED);
        }
        session.state = Some(state.into());
        current.launch_ticket_sha256 = Some(sha256_hex(ticket));
        current.launch_jti = Some(field(&launched, "jti")?.into());
        if open(url).is_err() {
            session.state = None;
            session.outcome = Some(Outcome::Unavailable);
            current.stop.store(true, Ordering::Release);
            return Err("The system browser could not open. Cancel this attempt and try again.");
        }
        Ok(())
    }

    fn validate_active_ticket(
        &self,
        current: &Running,
        context: &str,
        handle: &str,
        ticket: &str,
    ) -> Result<(), &'static str> {
        let value = ticket_payload(ticket, &self.key)?;
        if !equal(
            &sha256_hex(ticket),
            current.launch_ticket_sha256.as_deref().ok_or(REFUSED)?,
        ) {
            return Err(REFUSED);
        }
        validate_ticket_time(&value, "launch", &self.instance)?;
        validate_bound_fields(&value)?;
        if !equal(field(&value, "context")?, context)
            || !equal(field(&value, "context")?, &current.context)
            || !equal(
                field(&value, "jti")?,
                current.launch_jti.as_deref().ok_or(REFUSED)?,
            )
            || sha256_hex(handle) != field(&value, "native_handle_sha256")?
            || !equal(
                field(&value, "prepare_ticket_sha256")?,
                &current.prepare_ticket_sha256,
            )
            || !equal(field(&value, "prepare_jti")?, &current.prepare_jti)
        {
            return Err(REFUSED);
        }
        Ok(())
    }

    pub fn consume(
        &self,
        label: &str,
        caller: &str,
        handle: &str,
        context: &str,
        ticket: &str,
    ) -> Result<Outcome, &'static str> {
        authorize_caller(label, caller)?;
        let mut slot = self.running.lock().map_err(|_| REFUSED)?;
        let current = slot.as_ref().ok_or(REFUSED)?;
        if !equal(handle, &current.handle) || !equal(context, &current.context) {
            return Err(REFUSED);
        }
        self.validate_active_ticket(current, context, handle, ticket)?;
        let outcome = {
            let mut session = current.session.lock().map_err(|_| REFUSED)?;
            if Instant::now() >= session.deadline {
                session.outcome = Some(Outcome::Expired);
            }
            session.outcome.take()
        };
        if let Some(outcome) = outcome {
            drop(slot.take());
            Ok(outcome)
        } else {
            Ok(Outcome::Pending)
        }
    }

    pub fn cancel(
        &self,
        label: &str,
        caller: &str,
        handle: &str,
        context: &str,
        ticket: &str,
    ) -> Result<(), &'static str> {
        authorize_caller(label, caller)?;
        let mut slot = self.running.lock().map_err(|_| REFUSED)?;
        if let Some(current) = slot.as_ref() {
            if !equal(handle, &current.handle) || !equal(context, &current.context) {
                return Err(REFUSED);
            }
            let value = ticket_payload(ticket, &self.key)?;
            if current.launch_ticket_sha256.is_some() {
                if !equal(
                    &sha256_hex(ticket),
                    current.launch_ticket_sha256.as_deref().ok_or(REFUSED)?,
                ) || !equal(field(&value, "instance")?, &self.instance)
                    || !equal(field(&value, "context")?, context)
                    || !equal(
                        field(&value, "jti")?,
                        current.launch_jti.as_deref().ok_or(REFUSED)?,
                    )
                    || sha256_hex(handle) != field(&value, "native_handle_sha256")?
                {
                    return Err(REFUSED);
                }
            } else if !equal(&sha256_hex(ticket), &current.prepare_ticket_sha256)
                || !equal(field(&value, "instance")?, &self.instance)
                || !equal(field(&value, "context")?, context)
                || field(&value, "purpose")? != "prepare"
                || !equal(field(&value, "jti")?, &current.prepare_jti)
            {
                return Err(REFUSED);
            }
        }
        drop(slot.take());
        Ok(())
    }

    pub fn stop(&self) {
        if let Ok(mut slot) = self.running.lock() {
            drop(slot.take());
        }
    }
}

fn receive(
    listener: TcpListener,
    host: String,
    session: Arc<Mutex<Session>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        if let Ok(mut current) = session.lock() {
            if Instant::now() >= current.deadline {
                current.state = None;
                current.outcome = Some(Outcome::Expired);
                return;
            }
        } else {
            return;
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let parsed = if peer.ip().is_loopback() {
                    read_request(&mut stream, &stop)
                } else {
                    Err(REFUSED)
                }
                .and_then(|request| {
                    let current = session.lock().map_err(|_| REFUSED)?;
                    if Instant::now() >= current.deadline || current.outcome.is_some() {
                        return Err(REFUSED);
                    }
                    parse_callback(&request, &host, current.state.as_deref().ok_or(REFUSED)?)
                });
                let accepted = parsed.is_ok();
                if let Ok(outcome) = parsed {
                    if let Ok(mut current) = session.lock() {
                        current.state = None;
                        current.outcome = Some(outcome);
                    }
                }
                let message = if accepted {
                    "Return received. Close this tab and return to Lightwork to review the result."
                } else {
                    "Return not accepted. Return to Lightwork and start sign-in again if needed."
                };
                let body = format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Return to Lightwork</title><script>history.replaceState(null,'','/connections');</script><body><p>{message}</p></body></html>");
                let status = if accepted {
                    "200 OK"
                } else {
                    "400 Bad Request"
                };
                let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'sha256-dkzb9YU2mDkxI5QWsmMAhnMPN6oZWBx6UCgknMPFJ10='; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()); // pragma: allowlist secret -- public CSP script digest
                let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                let _ = stream.write_all(response.as_bytes());
                drop(stream);
                if accepted {
                    drop(listener);
                    while !stop.load(Ordering::Acquire) {
                        if let Ok(mut current) = session.lock() {
                            if Instant::now() >= current.deadline {
                                current.outcome = Some(Outcome::Expired);
                                return;
                            }
                        } else {
                            return;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                if let Ok(mut current) = session.lock() {
                    current.outcome = Some(Outcome::Unavailable);
                    current.state = None;
                }
                return;
            }
        }
    }
}

fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> Result<String, &'static str> {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|_| REFUSED)?;
    let started = Instant::now();
    let mut data = Vec::new();
    let mut block = [0_u8; 1024];
    while data.len() <= MAX_REQUEST
        && started.elapsed() < Duration::from_secs(1)
        && !stop.load(Ordering::Acquire)
    {
        let count = stream.read(&mut block).map_err(|_| REFUSED)?;
        if count == 0 {
            return Err(REFUSED);
        }
        data.extend_from_slice(&block[..count]);
        if data.len() > MAX_REQUEST {
            return Err(REFUSED);
        }
        if data.ends_with(b"\r\n\r\n") {
            return String::from_utf8(data).map_err(|_| REFUSED);
        }
    }
    Err(REFUSED)
}

fn parse_callback(
    request: &str,
    host: &str,
    expected_state: &str,
) -> Result<Outcome, &'static str> {
    if request.len() > MAX_REQUEST {
        return Err(REFUSED);
    }
    let mut lines = request.split("\r\n");
    let first = lines.next().ok_or(REFUSED)?;
    let parts: Vec<_> = first.split(' ').collect();
    if parts.len() != 3 || parts[0] != "GET" || !matches!(parts[2], "HTTP/1.1" | "HTTP/1.0") {
        return Err(REFUSED);
    }
    let raw_query = parts[1].strip_prefix("/connections?").ok_or(REFUSED)?;
    if raw_query.contains('#') {
        return Err(REFUSED);
    }
    let mut hosts = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':').ok_or(REFUSED)?;
        if key.eq_ignore_ascii_case("host") {
            hosts += 1;
            if value.trim() != host {
                return Err(REFUSED);
            }
        }
        if key.eq_ignore_ascii_case("transfer-encoding")
            || key.eq_ignore_ascii_case("content-length")
            || key.eq_ignore_ascii_case("origin")
        {
            return Err(REFUSED);
        }
    }
    if hosts != 1 {
        return Err(REFUSED);
    }
    let fields = query(raw_query)?;
    let state = fields.get("state").ok_or(REFUSED)?;
    if !token(state, 40, 64) || !equal(state, expected_state) {
        return Err(REFUSED);
    }
    match (fields.get("code"), fields.get("error")) {
        (Some(code), None) if !code.is_empty() && code.len() <= 8192 => Ok(Outcome::Returned {
            state: state.clone(),
            code: code.clone(),
        }),
        (None, Some(error)) if !error.is_empty() && error.len() <= 128 => Ok(Outcome::Denied),
        _ => Err(REFUSED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CONTEXT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const STATE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEXT_STATE: &str = "ddddddddddddddddddddddddddddddddddddddddddd";
    const CHALLENGE: &str = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
    const PREPARE_JTI: &str = "ppppppppppppppppppppppppppppppppppppppppppp";
    const LAUNCH_JTI: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

    fn quote(value: &str) -> String {
        let mut result = String::new();
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                result.push(char::from(byte));
            } else if byte == b' ' {
                result.push('+');
            } else {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
        result
    }

    fn signed(fields: &Ticket, key: &[u8; 32]) -> String {
        let clear = fields
            .iter()
            .map(|(name, value)| format!("{}={}", quote(name), quote(value)))
            .collect::<Vec<_>>()
            .join("&");
        let body: String = clear
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let signature: String = hmac_sha256(key, body.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("{body}.{signature}")
    }

    fn prepare_token(broker: &Broker, jti: &str, issued_at: u64, expires_at: u64) -> String {
        let mut fields = Ticket::new();
        for (name, value) in [
            ("schema", TICKET_SCHEMA.to_owned()),
            ("purpose", "prepare".to_owned()),
            ("instance", broker.instance.clone()),
            ("tenant_sha256", sha256_hex("tenant-a")),
            ("principal_sha256", sha256_hex("user:owner")),
            ("context", CONTEXT.to_owned()),
            ("profile", "google-drive".to_owned()),
            ("provider", "google".to_owned()),
            ("client_id_sha256", sha256_hex("synthetic")),
            ("callback_uri", CALLBACK.to_owned()),
            (
                "scopes",
                "openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.readonly".to_owned(),
            ),
            ("name_sha256", sha256_hex("drive")),
            ("site_url_sha256", sha256_hex("")),
            ("expected_revision_sha256", sha256_hex("")),
            ("jti", jti.to_owned()),
            ("issued_at", issued_at.to_string()),
            ("expires_at", expires_at.to_string()),
        ] {
            fields.insert(name.to_owned(), value);
        }
        signed(&fields, &broker.key)
    }

    fn authorization(state: &str) -> String {
        format!("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=synthetic&redirect_uri=http%3A%2F%2F127.0.0.1%3A8766%2Fconnections&code_challenge={CHALLENGE}&code_challenge_method=S256&scope=openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.readonly&state={state}&access_type=offline&prompt=consent")
    }

    fn launch_token(
        broker: &Broker,
        prepare: &str,
        handle: &str,
        state: &str,
        authorize_url: &str,
        jti: &str,
    ) -> String {
        let mut fields = ticket_payload(prepare, &broker.key).unwrap();
        let prepare_jti = field(&fields, "jti").unwrap().to_owned();
        for name in ["purpose", "jti", "issued_at", "expires_at"] {
            fields.remove(name);
        }
        let now = unix_time().unwrap();
        for (name, value) in [
            ("purpose", "launch".to_owned()),
            ("consent_sha256", sha256_hex(state)),
            ("state", state.to_owned()),
            ("pkce_challenge", CHALLENGE.to_owned()),
            ("authorize_url_sha256", sha256_hex(authorize_url)),
            ("native_handle_sha256", sha256_hex(handle)),
            ("prepare_ticket_sha256", sha256_hex(prepare)),
            ("prepare_jti", prepare_jti),
            ("jti", jti.to_owned()),
            ("issued_at", now.to_string()),
            ("expires_at", (now + 600).to_string()),
        ] {
            fields.insert(name.to_owned(), value);
        }
        signed(&fields, &broker.key)
    }

    fn request(host: &str, params: &str) -> String {
        format!("GET /connections?{params} HTTP/1.1\r\nHost: {host}\r\n\r\n")
    }

    fn response(host: &str, params: &str) -> String {
        let mut stream = TcpStream::connect(host).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request(host, params).as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn broker(
        lifetime: Duration,
        state: &str,
        prepare_jti: &str,
        launch_jti: &str,
    ) -> (Broker, String, String, String, String, String) {
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = reservation.local_addr().unwrap().to_string();
        drop(reservation);
        let broker = Broker::with_key([7; 32]);
        let now = unix_time().unwrap();
        let prepare = prepare_token(&broker, prepare_jti, now, now + 600);
        let handle = broker
            .prepare_on(CONTEXT, &prepare, prepare_jti, &host, lifetime)
            .unwrap();
        let url = authorization(state);
        let launch = launch_token(&broker, &prepare, &handle, state, &url, launch_jti);
        (broker, handle, host, prepare, launch, url)
    }

    #[test]
    fn cryptography_matches_standard_vectors() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" // pragma: allowlist secret -- SHA-256 test vector
        );
        assert_eq!(
            hmac_sha256(&[7; 32], b"payload")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "3edb2ff2999b660a1a2c8659d65745afb24d7bb5924855188740fcffd6de8f1b" // pragma: allowlist secret -- SHA-256 test vector
        );
    }

    #[test]
    fn profile_scope_contract_accepts_current_identity_scopes_only() {
        assert!(valid_profile(
            "google-drive",
            "google",
            "openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.readonly",
        ));
        assert!(valid_profile(
            "jira-cloud",
            "atlassian",
            "read:me read:jira-work write:jira-work offline_access",
        ));
        assert!(!valid_profile(
            "google-drive",
            "google",
            "https://www.googleapis.com/auth/drive.readonly",
        ));
    }

    #[test]
    fn exact_caller_and_ticket_instance_context_expiry_and_signature_are_required() {
        assert!(authorize_caller("main", CALLER).is_ok());
        for url in [
            "http://localhost:8765/connections",
            "http://127.0.0.1:8765/connections?x=1",
            "https://example.test/connections",
        ] {
            assert!(authorize_caller("main", url).is_err());
        }
        let broker = Broker::with_key([7; 32]);
        let now = unix_time().unwrap();
        let valid = prepare_token(&broker, PREPARE_JTI, now, now + 600);
        assert!(prepare_ticket(&valid, &broker.key, &broker.instance, CONTEXT).is_ok());
        let other = Broker::with_key([8; 32]);
        assert!(prepare_ticket(&valid, &other.key, &other.instance, CONTEXT).is_err());
        assert!(prepare_ticket(&valid, &broker.key, &broker.instance, &"c".repeat(64)).is_err());
        let mut tampered = valid.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
        assert!(prepare_ticket(
            std::str::from_utf8(&tampered).unwrap(),
            &broker.key,
            &broker.instance,
            CONTEXT
        )
        .is_err());
        let expired = prepare_token(&broker, PREPARE_JTI, now - 601, now - 1);
        assert!(prepare_ticket(&expired, &broker.key, &broker.instance, CONTEXT).is_err());
    }

    #[test]
    fn launch_is_ticket_bound_to_endpoint_state_callback_client_pkce_scope_and_profile() {
        for mutation in 0..8 {
            let (broker, handle, _host, _prepare, launch, url) =
                broker(Duration::from_secs(2), STATE, PREPARE_JTI, LAUNCH_JTI);
            let changed = match mutation {
                0 => url.replace("accounts.google.com", "accounts.google.com.evil.test"),
                1 => url.replace("8766", "8767"),
                2 => url.replace("S256", "plain"),
                3 => format!("{url}&state={STATE}"),
                4 => format!("{url}#fragment"),
                5 => url.replace("client_id=synthetic", "client_id=other"),
                6 => url.replace("drive.readonly", "drive"),
                _ => url.replace("https://", "http://"),
            };
            assert!(broker
                .launch(
                    "main",
                    CALLER,
                    &handle,
                    CONTEXT,
                    &changed,
                    STATE,
                    &launch,
                    |_| panic!("must not open browser")
                )
                .is_err());
        }
    }

    #[test]
    fn callback_parser_rejects_smuggling_and_never_echoes_secrets() {
        let base = request(
            "127.0.0.1:8766",
            &format!("state={STATE}&code=synthetic-code"),
        );
        assert!(matches!(
            parse_callback(&base, "127.0.0.1:8766", STATE),
            Ok(Outcome::Returned { .. })
        ));
        for changed in [
            base.replace("GET", "POST"),
            base.replace("/connections?", "/wrong?"),
            base.replace("Host: 127.0.0.1:8766", "Host: localhost:8766"),
            base.replace("state=", "state=x"),
            base.replace("&code=", &format!("&%73tate={STATE}&code=")),
            base.replace("&code=", "&error=access_denied&code="),
            base.replace("synthetic-code", "%00secret"),
            base.replace("\r\n\r\n", "\r\nOrigin: https://evil.test\r\n\r\n"),
        ] {
            assert!(parse_callback(&changed, "127.0.0.1:8766", STATE).is_err());
        }
    }

    #[test]
    fn loopback_return_and_launch_ticket_are_one_shot() {
        let (broker, handle, host, _prepare, launch, url) =
            broker(Duration::from_secs(2), STATE, PREPARE_JTI, LAUNCH_JTI);
        broker
            .launch(
                "main",
                CALLER,
                &handle,
                CONTEXT,
                &url,
                STATE,
                &launch,
                |_| Ok(()),
            )
            .unwrap();
        assert!(broker
            .launch(
                "main",
                CALLER,
                &handle,
                CONTEXT,
                &url,
                STATE,
                &launch,
                |_| panic!("must not reopen")
            )
            .is_err());
        let response = response(&host, &format!("state={STATE}&code=synthetic-private-code"));
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(!response.contains(STATE) && !response.contains("synthetic-private-code"));
        assert!(
            matches!(broker.consume("main", CALLER, &handle, CONTEXT, &launch), Ok(Outcome::Returned { state, code }) if state == STATE && code == "synthetic-private-code")
        );
        assert!(broker
            .consume("main", CALLER, &handle, CONTEXT, &launch)
            .is_err());
        assert!(TcpListener::bind(&host).is_ok());
    }

    #[test]
    fn cancel_requires_exact_ticket_and_confirms_listener_closure() {
        let (broker, handle, host, prepare, _launch, _url) =
            broker(Duration::from_secs(2), STATE, PREPARE_JTI, LAUNCH_JTI);
        let now = unix_time().unwrap();
        let other = prepare_token(
            &broker,
            "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr",
            now,
            now + 600,
        );
        assert!(broker
            .cancel("main", CALLER, &handle, CONTEXT, &other)
            .is_err());
        assert!(TcpListener::bind(&host).is_err());
        broker
            .cancel("main", CALLER, &handle, CONTEXT, &prepare)
            .unwrap();
        assert!(TcpListener::bind(&host).is_ok());
    }

    #[test]
    fn denied_old_callback_cannot_complete_the_next_attempt() {
        let (broker, handle, host, _prepare, launch, url) =
            broker(Duration::from_secs(2), STATE, PREPARE_JTI, LAUNCH_JTI);
        broker
            .launch(
                "main",
                CALLER,
                &handle,
                CONTEXT,
                &url,
                STATE,
                &launch,
                |_| Ok(()),
            )
            .unwrap();
        assert!(
            response(&host, &format!("state={STATE}&error=access_denied"))
                .starts_with("HTTP/1.1 200")
        );
        assert!(matches!(
            broker.consume("main", CALLER, &handle, CONTEXT, &launch),
            Ok(Outcome::Denied)
        ));
        let now = unix_time().unwrap();
        let next_jti = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";
        let prepare = prepare_token(&broker, next_jti, now, now + 600);
        let next_handle = broker
            .prepare_on(CONTEXT, &prepare, next_jti, &host, Duration::from_secs(2))
            .unwrap();
        let next_url = authorization(NEXT_STATE);
        let next_launch = launch_token(
            &broker,
            &prepare,
            &next_handle,
            NEXT_STATE,
            &next_url,
            "sssssssssssssssssssssssssssssssssssssssssss",
        );
        broker
            .launch(
                "main",
                CALLER,
                &next_handle,
                CONTEXT,
                &next_url,
                NEXT_STATE,
                &next_launch,
                |_| Ok(()),
            )
            .unwrap();
        assert!(
            response(&host, &format!("state={STATE}&code=late-code")).starts_with("HTTP/1.1 400")
        );
        assert!(
            response(&host, &format!("state={NEXT_STATE}&code=new-code"))
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            matches!(broker.consume("main", CALLER, &next_handle, CONTEXT, &next_launch), Ok(Outcome::Returned { state, code }) if state == NEXT_STATE && code == "new-code")
        );
    }

    #[test]
    fn expired_receiver_is_evicted_for_a_new_attempt() {
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = reservation.local_addr().unwrap().to_string();
        drop(reservation);
        let broker = Broker::with_key([7; 32]);
        let now = unix_time().unwrap();
        let prepare = prepare_token(&broker, PREPARE_JTI, now, now + 600);
        broker
            .prepare_on(
                CONTEXT,
                &prepare,
                PREPARE_JTI,
                &host,
                Duration::from_millis(30),
            )
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let next_jti = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";
        let next = prepare_token(&broker, next_jti, now, now + 600);
        let handle = broker
            .prepare_on(CONTEXT, &next, next_jti, &host, Duration::from_secs(2))
            .unwrap();
        broker
            .cancel("main", CALLER, &handle, CONTEXT, &next)
            .unwrap();
        assert!(TcpListener::bind(&host).is_ok());
    }

    #[test]
    fn failed_browser_launch_cannot_replay_and_remains_cancellable() {
        let (broker, handle, host, _prepare, launch, url) =
            broker(Duration::from_secs(2), STATE, PREPARE_JTI, LAUNCH_JTI);
        assert!(broker
            .launch(
                "main",
                CALLER,
                &handle,
                CONTEXT,
                &url,
                STATE,
                &launch,
                |_| Err("synthetic-private-error")
            )
            .is_err());
        assert!(broker
            .launch(
                "main",
                CALLER,
                &handle,
                CONTEXT,
                &url,
                STATE,
                &launch,
                |_| panic!("must not reopen")
            )
            .is_err());
        broker
            .cancel("main", CALLER, &handle, CONTEXT, &launch)
            .unwrap();
        assert!(TcpListener::bind(&host).is_ok());
    }
}
