use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CANONICAL_REPOSITORY: &str = "Daybreak-AI-Labs/LightworkOS";
const CANONICAL_REMOTE_URLS: &[&str] = &[
    "https://github.com/Daybreak-AI-Labs/LightworkOS",
    "https://github.com/Daybreak-AI-Labs/LightworkOS.git",
    "git@github.com:Daybreak-AI-Labs/LightworkOS.git",
    "ssh://git@github.com/Daybreak-AI-Labs/LightworkOS.git",
];
const INSTALLER_ROOT: &str = "apps/installer-desktop";
const RUNTIME_ROOT: &str = "apps/desktop-runtime";
const SHELL_INSTALLER: &str = "deploy/desktop/install.sh";
const POWERSHELL_INSTALLER: &str = "deploy/desktop/install.ps1";
const GENERATED_PATHS: &[&str] = &[
    "apps/installer-desktop/coverage",
    "apps/installer-desktop/dist",
    "apps/installer-desktop/node_modules",
    "apps/installer-desktop/provenance",
    "apps/installer-desktop/src-tauri/gen",
    "apps/installer-desktop/src-tauri/target",
    "apps/desktop-runtime/target",
];

fn main() {
    println!("cargo:rerun-if-env-changed=MAVERICK_INSTALL_REF");
    println!("cargo:rerun-if-env-changed=MAVERICK_REQUIRE_CLEAN_INSTALLER_SOURCE");
    println!("cargo:rerun-if-changed=../../../{SHELL_INSTALLER}");
    println!("cargo:rerun-if-changed=../../../{POWERSHELL_INSTALLER}");

    let repository_root = repository_root();
    emit_git_rerun_triggers(&repository_root);
    verify_canonical_repository(&repository_root);

    let head = validate_install_ref(&current_git_commit(&repository_root));
    emit_source_rerun_triggers(&repository_root, &head);
    let install_ref = std::env::var("MAVERICK_INSTALL_REF")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| head.clone());
    let install_ref = validate_install_ref(&install_ref);
    verify_commit(&repository_root, &install_ref);
    verify_install_ref_ancestor(&repository_root, &install_ref, &head);

    if require_clean_source() {
        verify_clean_source(&repository_root, &head, &install_ref);
    }

    // Embed canonical commit blobs, never worktree bytes. Both the git object
    // replacement mechanism and inherited GIT_* routing variables are disabled
    // by git_command(), so the displayed revision names the bytes we stage.
    let shell = committed_blob(&repository_root, &install_ref, SHELL_INSTALLER);
    let powershell = committed_blob(&repository_root, &install_ref, POWERSHELL_INSTALLER);
    let out_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo did not provide OUT_DIR"));
    fs::write(out_dir.join("install.sh"), &shell)
        .expect("could not stage the committed shell installer blob");
    fs::write(out_dir.join("install.ps1"), &powershell)
        .expect("could not stage the committed PowerShell installer blob");

    println!("cargo:rustc-env=MAVERICK_INSTALL_REF={install_ref}");
    println!(
        "cargo:rustc-env=MAVERICK_INSTALL_SH_SHA256={}",
        sha256_hex(&shell)
    );
    println!(
        "cargo:rustc-env=MAVERICK_INSTALL_PS1_SHA256={}",
        sha256_hex(&powershell)
    );

    tauri_build::build();
}

fn validate_install_ref(value: &str) -> String {
    let trimmed = value.trim();
    let valid = trimmed.len() == 40
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        panic!("MAVERICK_INSTALL_REF must be a lowercase, full 40-character commit SHA");
    }
    trimmed.to_owned()
}

fn repository_root() -> PathBuf {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not provide CARGO_MANIFEST_DIR"),
    );
    manifest_dir
        .join("../../..")
        .canonicalize()
        .expect("could not resolve the Lightwork repository root")
}

fn git_command(repository_root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(repository_root)
        .arg("--no-replace-objects")
        .args(args);
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn git_output(repository_root: &Path, args: &[&str]) -> Output {
    git_command(repository_root, args)
        .output()
        .unwrap_or_else(|error| panic!("git {} could not start: {error}", args.join(" ")))
}

fn successful_git_output(repository_root: &Path, args: &[&str]) -> Output {
    let output = git_output(repository_root, args);
    if !output.status.success() {
        panic!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    output
}

fn git_utf8(repository_root: &Path, args: &[&str]) -> String {
    String::from_utf8(successful_git_output(repository_root, args).stdout)
        .unwrap_or_else(|_| panic!("git {} did not emit UTF-8", args.join(" ")))
        .trim()
        .to_owned()
}

fn current_git_commit(repository_root: &Path) -> String {
    git_utf8(repository_root, &["rev-parse", "HEAD"])
}

fn verify_commit(repository_root: &Path, install_ref: &str) {
    let commit_expression = format!("{install_ref}^{{commit}}");
    let resolved = git_utf8(
        repository_root,
        &["rev-parse", "--verify", &commit_expression],
    );
    if resolved != install_ref {
        panic!("MAVERICK_INSTALL_REF does not resolve to the exact requested commit");
    }
}

fn verify_install_ref_ancestor(repository_root: &Path, install_ref: &str, head: &str) {
    let output = git_output(
        repository_root,
        &["merge-base", "--is-ancestor", install_ref, head],
    );
    match output.status.code() {
        Some(0) => {}
        Some(1) => {
            panic!("MAVERICK_INSTALL_REF must be an ancestor of the current Lightwork HEAD")
        }
        _ => panic!(
            "git merge-base --is-ancestor failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

fn verify_canonical_repository(repository_root: &Path) {
    let remote = git_utf8(
        repository_root,
        &[
            "config",
            "--local",
            "--no-includes",
            "--get",
            "remote.origin.url",
        ],
    );
    if !CANONICAL_REMOTE_URLS.contains(&remote.as_str()) {
        panic!(
            "desktop installers must be built from the canonical {CANONICAL_REPOSITORY} origin, not {remote}"
        );
    }
}

fn committed_blob(repository_root: &Path, install_ref: &str, repository_path: &str) -> Vec<u8> {
    let object = format!("{install_ref}:{repository_path}");
    successful_git_output(repository_root, &["cat-file", "blob", &object]).stdout
}

fn require_clean_source() -> bool {
    match std::env::var("MAVERICK_REQUIRE_CLEAN_INSTALLER_SOURCE") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if matches!(value.trim(), "1" | "true" | "TRUE") => true,
        Ok(value) if matches!(value.trim(), "0" | "false" | "FALSE" | "") => false,
        Ok(_) => {
            panic!("MAVERICK_REQUIRE_CLEAN_INSTALLER_SOURCE must be one of 1, 0, true, or false")
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("MAVERICK_REQUIRE_CLEAN_INSTALLER_SOURCE must be UTF-8")
        }
    }
}

fn verify_clean_source(repository_root: &Path, head: &str, install_ref: &str) {
    if head != install_ref {
        panic!("release-grade installer builds require MAVERICK_INSTALL_REF to equal HEAD");
    }
    verify_raw_source_snapshot(repository_root, install_ref);
}

fn tracked_blobs(repository_root: &Path, install_ref: &str) -> BTreeMap<String, String> {
    let output = successful_git_output(
        repository_root,
        &[
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            install_ref,
            "--",
            INSTALLER_ROOT,
            RUNTIME_ROOT,
            SHELL_INSTALLER,
            POWERSHELL_INSTALLER,
        ],
    )
    .stdout;
    let text = String::from_utf8(output).expect("git ls-tree did not emit UTF-8 paths");
    let mut tracked = BTreeMap::new();
    for record in text.split('\0').filter(|record| !record.is_empty()) {
        let (metadata, repository_path) = record
            .split_once('\t')
            .unwrap_or_else(|| panic!("git ls-tree emitted a malformed record"));
        let mut fields = metadata.split(' ');
        let mode = fields.next().unwrap_or_default();
        let object_type = fields.next().unwrap_or_default();
        let object_id = fields.next().unwrap_or_default();
        let valid_object_id = matches!(object_id.len(), 40 | 64)
            && object_id.bytes().all(|byte| byte.is_ascii_hexdigit());
        if fields.next().is_some()
            || !valid_object_id
            || mode.len() != 6
            || !mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
        {
            panic!("git ls-tree emitted malformed metadata for {repository_path}");
        }
        if object_type != "blob" || mode == "120000" {
            panic!(
                "tracked installer source must be a regular blob, not {mode} {object_type}: {repository_path}"
            );
        }
        if !is_scoped_repository_path(repository_path) {
            panic!("git ls-tree escaped the verified source scope: {repository_path}");
        }
        if is_generated_path(repository_path) {
            panic!("generated build output must not be tracked: {repository_path}");
        }
        tracked.insert(repository_path.to_owned(), object_id.to_owned());
    }
    for required in [SHELL_INSTALLER, POWERSHELL_INSTALLER] {
        if !tracked.contains_key(required) {
            panic!("required bootstrap is absent from {install_ref}: {required}");
        }
    }
    tracked
}

fn is_scoped_repository_path(repository_path: &str) -> bool {
    let valid_components = !repository_path.starts_with('/')
        && !repository_path.contains('\\')
        && repository_path
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."));
    valid_components
        && (repository_path.starts_with(&format!("{INSTALLER_ROOT}/"))
            || repository_path.starts_with(&format!("{RUNTIME_ROOT}/"))
            || repository_path == SHELL_INSTALLER
            || repository_path == POWERSHELL_INSTALLER)
}

fn is_generated_path(repository_path: &str) -> bool {
    repository_path.ends_with(".tsbuildinfo")
        || GENERATED_PATHS.iter().any(|generated| {
            repository_path == *generated
                || repository_path
                    .strip_prefix(generated)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn repository_path(repository_root: &Path, path: &Path) -> String {
    path.strip_prefix(repository_root)
        .expect("verified source path escaped the repository root")
        .to_str()
        .expect("verified source paths must be UTF-8")
        .replace('\\', "/")
}

fn collect_directory_files(repository_root: &Path, directory: &Path, files: &mut BTreeSet<String>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("could not enumerate {}: {error}", directory.display()));
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = repository_path(repository_root, &path);
        if is_generated_path(&relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("could not inspect {}: {error}", path.display()));
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            panic!("symbolic links are not allowed in verified source: {relative}");
        }
        if file_type.is_dir() {
            collect_directory_files(repository_root, &path, files);
        } else if file_type.is_file() {
            files.insert(relative);
        } else {
            panic!("unsupported filesystem entry in verified source: {relative}");
        }
    }
}

fn worktree_files(repository_root: &Path) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    for root in [INSTALLER_ROOT, RUNTIME_ROOT] {
        collect_directory_files(repository_root, &repository_root.join(root), &mut files);
    }
    for required in [SHELL_INSTALLER, POWERSHELL_INSTALLER] {
        let path = repository_root.join(required);
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("could not inspect {}: {error}", path.display()));
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            panic!("required bootstrap is not a regular file: {required}");
        }
        files.insert(required.to_owned());
    }
    files
}

fn verify_raw_source_snapshot(repository_root: &Path, install_ref: &str) {
    let tracked = tracked_blobs(repository_root, install_ref);
    let actual = worktree_files(repository_root);
    let expected = tracked.keys().cloned().collect::<BTreeSet<_>>();
    let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
    if !missing.is_empty() || !unexpected.is_empty() {
        panic!(
            "release-grade installer source file set differs from {install_ref}; missing: {}; untracked: {}",
            missing.join(", "),
            unexpected.join(", ")
        );
    }

    for (repository_path, object_id) in tracked {
        let committed =
            successful_git_output(repository_root, &["cat-file", "blob", &object_id]).stdout;
        let worktree = fs::read(repository_root.join(&repository_path)).unwrap_or_else(|error| {
            panic!("could not read verified source {repository_path}: {error}")
        });
        if worktree != committed {
            panic!("raw worktree bytes differ from {install_ref}: {repository_path}");
        }
    }
}

fn emit_git_rerun_triggers(repository_root: &Path) {
    let git_dir = absolute_git_path(
        repository_root,
        &git_utf8(repository_root, &["rev-parse", "--absolute-git-dir"]),
    );
    let common_dir = absolute_git_path(
        repository_root,
        &git_utf8(repository_root, &["rev-parse", "--git-common-dir"]),
    );
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    println!(
        "cargo:rerun-if-changed={}",
        common_dir.join("packed-refs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        common_dir.join("config").display()
    );

    let symbolic = git_output(repository_root, &["symbolic-ref", "-q", "HEAD"]);
    match symbolic.status.code() {
        Some(0) => {
            let reference = String::from_utf8(symbolic.stdout)
                .expect("git symbolic-ref did not emit UTF-8")
                .trim()
                .to_owned();
            if !reference.starts_with("refs/") || reference.contains("..") {
                panic!("git symbolic-ref emitted an unsafe ref path");
            }
            println!(
                "cargo:rerun-if-changed={}",
                common_dir.join(reference).display()
            );
        }
        Some(1) => {}
        _ => panic!(
            "git symbolic-ref failed: {}",
            String::from_utf8_lossy(&symbolic.stderr).trim()
        ),
    }
}

fn emit_source_rerun_triggers(repository_root: &Path, head: &str) {
    // Once a build script emits any rerun directive, Cargo no longer falls
    // back to watching the whole package. Watch every committed source input
    // explicitly so a dirty edit or deletion cannot reuse a prior successful
    // provenance decision merely because HEAD itself did not move.
    for repository_path in tracked_blobs(repository_root, head).keys() {
        println!(
            "cargo:rerun-if-changed={}",
            repository_root.join(repository_path).display()
        );
    }
}

fn absolute_git_path(repository_root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        repository_root.join(path)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
