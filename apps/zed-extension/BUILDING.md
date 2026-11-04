# Reproducible Zed preview bundle

This is a **preview**, pending installation and MCP qualification in the exact
Zed release selected by the release owner. It does not install or run Lightwork,
change credentials, publish an extension or claim marketplace availability.

The build uses Rust **1.97.1**, `wasm32-wasip2`, exact
`zed_extension_api =0.7.0` and the committed Cargo lock. The API's documented
context-server hook returns the unchanged `maverick mcp` command. The current
[Zed development guide](https://zed.dev/docs/extensions/developing-extensions)
specifies this WASI target; hosts must support the pinned API generation.

From this directory, with Python 3.11+ and the pinned Rust toolchain installed:

```sh
python build.py
```

The command runs `cargo build --locked --release --target wasm32-wasip2`, verifies
the component header and writes `build/lightwork-zed-preview.zip` and its SHA256.
The archive contains `extension.wasm`, the complete source/lock/task inputs, the
`LICENSE` and `NOTICE` files and a build manifest with compiler versions and
each file's SHA256. Archive order and timestamps are normalized. It is a
release-engineering input, not a signed store installer. Cargo may fetch
public locked dependencies on the first build. Rustup may fetch the pinned
toolchain/target when absent. The build script does not invoke an installer or
change Rust defaults.

For local installed-host qualification, use Zed **Extensions → Install Dev
Extension** and select this source directory (or the extracted source bundle).
Zed performs its own extension build. Installing a dev extension can replace an
existing installed extension with the same ID; perform qualification in a test
profile. Confirm the exact Zed build accepts API0.7.0 and record its version.
Use a synthetic Lightwork profile and mock services to check MCP discovery,
missing CLI, denied/revoked access, process disposal and accessible recovery.
Terminal tasks remain an explicit separate user installation.

For an end-user release, a release owner must qualify the exact host matrix,
select and approve the distribution mechanism and publish through the existing
authorized release process. A passing WASM compile alone does not meet that gate.
