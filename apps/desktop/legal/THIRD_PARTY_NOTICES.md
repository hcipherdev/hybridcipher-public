# HybridCipher Third-Party Notices

Updated: 2026-04-05

This document is the curated third-party notice for the public HybridCipher
desktop repository surface. It covers the major direct third-party components
and vendored assets used by the desktop app, public Rust crates, and the
optional feedback API included in this repository.

This file is not a substitute for release-time license generation. Any shipped
desktop bundle, installer, CLI package, or deployed feedback API should also
include an exhaustive transitive dependency notice generated from the exact
`Cargo.lock` and npm lockfiles used to build that artifact.

## Cryptography and Security Components

- `aws-lc-rs` 1.13.3
  Purpose: Rust bindings for AWS-LC, used as the implementation backend for
  ML-KEM-768 operations in HybridCipher's hybrid PQC flow.
  License: `ISC AND (Apache-2.0 OR ISC)`
  Upstream: <https://github.com/aws/aws-lc-rs>

- `aws-lc-sys` 0.30.0
  Purpose: Low-level FFI bindings to AWS-LC used by the same ML-KEM-768
  integration layer.
  License: `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`
  Upstream: <https://github.com/aws/aws-lc-rs>

- `x25519-dalek` 2.0.1
  Purpose: Classical X25519 key agreement used alongside the PQ KEM path.
  License: `BSD-3-Clause`
  Upstream: <https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek>

- `ed25519-dalek` 2.2.0
  Purpose: Ed25519 signature support used by public HybridCipher components.
  License: `BSD-3-Clause`
  Upstream: <https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek>

- `opaque-ke` 3.0.0
  Purpose: OPAQUE password-authenticated key exchange used by the client and
  desktop authentication flows.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/facebook/opaque-ke>

- `argon2` 0.5.3
  Purpose: Password hashing and hardening support.
  License: `MIT OR Apache-2.0`
  Upstream: <https://github.com/RustCrypto/password-hashes/tree/master/argon2>

- `chacha20poly1305` 0.10.1
  Purpose: Authenticated encryption in public cryptographic workflows.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305>

- `hkdf` 0.12.4 and `sha2` 0.10.9
  Purpose: Key derivation and hashing support in the public crypto layer.
  License: `MIT OR Apache-2.0`
  Upstream: <https://github.com/RustCrypto/KDFs/> and
  <https://github.com/RustCrypto/hashes>

- `secrecy` 0.8.0 and `zeroize` 1.8.1
  Purpose: Secret-memory handling and zeroization support.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/iqlusioninc/crates/tree/main/secrecy> and
  <https://github.com/RustCrypto/utils/tree/master/zeroize>

## Desktop Framework and Runtime

- `tauri` 2.9.1 and `tauri-build` 2.5.1
  Purpose: Core desktop application framework and build integration.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/tauri-apps/tauri>

- `tauri-plugin-dialog` 2.4.0
  Purpose: Native open/save dialogs.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/tauri-apps/plugins-workspace>

- `tauri-plugin-fs` 2.4.2
  Purpose: File-system access helpers for the desktop app.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/tauri-apps/plugins-workspace>

- `tauri-plugin-shell` 2.3.1
  Purpose: Controlled shell and URL opening integrations.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/tauri-apps/plugins-workspace>

- `tauri-plugin-updater` 2.9.0
  Purpose: Desktop update delivery support.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/tauri-apps/plugins-workspace>

- `tokio` 1.47.1
  Purpose: Async runtime used by the public desktop and CLI code.
  License: `MIT`
  Upstream: <https://github.com/tokio-rs/tokio>

- `reqwest` 0.11.27 and 0.12.23
  Purpose: HTTP client support. The current public workspace resolves both
  versions in different parts of the dependency graph.
  License: `MIT OR Apache-2.0`
  Upstream: <https://github.com/seanmonstar/reqwest>

- `serde` 1.0.228 and `serde_json` 1.0.145
  Purpose: Serialization and JSON encoding across the public app surface.
  License: `MIT OR Apache-2.0`
  Upstream: <https://github.com/serde-rs/serde> and
  <https://github.com/serde-rs/json>

- `keyring` 2.3.3 and 3.6.3
  Purpose: Secure credential storage integrations. The current public
  workspace resolves both versions in the dependency graph.
  License: `MIT OR Apache-2.0`
  Upstream: <https://github.com/hwchen/keyring-rs.git>

- `portable-pty` 0.8.1
  Purpose: Pseudo-terminal support for desktop terminal/session features.
  License: `MIT`
  Upstream: <https://github.com/wez/wezterm>

- `notify` 6.1.1
  Purpose: File-watching support.
  License: `CC0-1.0`
  Upstream: <https://github.com/notify-rs/notify.git>

- `sled` 0.34.7
  Purpose: Embedded local storage used by public application components.
  License: `MIT/Apache-2.0`
  Upstream: <https://github.com/spacejam/sled>

## Vendored Frontend Assets

- `xterm.js`
  Purpose: Browser terminal frontend used by the desktop application UI.
  License: `MIT`
  Upstream: <https://github.com/xtermjs/xterm.js>
  Source location in this repository:
  `apps/desktop/src/vendor/xterm/xterm.js`
  Version note: the vendored file does not record an upstream package version.

- `xterm-addon-fit`
  Purpose: Terminal sizing addon used with `xterm.js`.
  License: `MIT`
  Upstream: <https://github.com/xtermjs/xterm.js>
  Source location in this repository:
  `apps/desktop/src/vendor/xterm/xterm-addon-fit.js`
  Version note: the vendored file does not record an upstream package version.

- `xterm.css`
  Purpose: CSS stylesheet used by the vendored terminal frontend.
  License: `MIT`
  Upstream: <https://github.com/xtermjs/xterm.js>
  Source location in this repository:
  `apps/desktop/src/vendor/xterm/xterm.css`
  Note: the vendored stylesheet includes the upstream MIT notice header.

## Desktop Build Tooling

- `@tauri-apps/cli` 2.10.1
  Purpose: Desktop build, signing, and packaging tooling.
  License: `Apache-2.0 OR MIT`
  Upstream: <https://github.com/tauri-apps/tauri>

- `sharp` 0.34.5
  Purpose: Image processing used by desktop asset generation scripts.
  License: `Apache-2.0`
  Upstream: <https://github.com/lovell/sharp>

- `png-to-ico` 3.0.1
  Purpose: Icon conversion utility used by desktop packaging workflows.
  License: `MIT`
  Upstream: <https://github.com/steambap/png-to-ico>

## Optional Feedback API

- `express` `^4.18.2`
  Purpose: HTTP server for the optional feedback API.
  License: expected upstream package metadata is `MIT`
  Upstream: <https://github.com/expressjs/express>

- `cors` `^2.8.5`
  Purpose: CORS middleware for the optional feedback API.
  License: expected upstream package metadata is `MIT`
  Upstream: <https://github.com/expressjs/cors>

- `nodemailer` `^6.9.7`
  Purpose: Email delivery integration for the optional feedback API.
  License: expected upstream package metadata is `MIT`
  Upstream: <https://github.com/nodemailer/nodemailer>

The feedback API currently records version ranges in `package.json` and does
not commit a `package-lock.json`. Before distributing or deploying that service,
generate notices from the exact resolved dependency tree used in that build.
