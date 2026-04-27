# HybridCipher

HybridCipher protects shared files before they leave the device.

It is built for teams that need client-side encryption, explicit device trust,
and a post-quantum migration path without asking the cloud service to handle
plaintext files. The desktop app and bundled `hybridcipher` CLI give users two
entry points into the same local client engine: files are encrypted, decrypted,
checked, and trusted on the user's device before encrypted coordination data is
sent to the cloud.

## Why HybridCipher Exists

Most file-sharing systems make the cloud service part of the trust boundary.
HybridCipher is designed for a stricter model: user devices do the sensitive
cryptographic work locally, while the cloud service coordinates encrypted
collaboration, metadata, device state, and recovery workflows.

That separation helps teams reduce the impact of server compromise, stolen
devices, and long-term cryptographic migration pressure.

## Who It Is For

HybridCipher is for teams and builders who need stronger guarantees than
ordinary cloud sync:

- organizations sharing sensitive files across trusted devices
- security-conscious teams that want client-side encryption by default
- operators who need visible device trust, recovery, and coverage workflows
- developers and auditors who want to inspect the public client implementation

## What It Protects Against

HybridCipher is designed to keep plaintext and local secrets on trusted user
devices. The cloud coordination service should receive ciphertext, metadata,
and encrypted coordination artifacts, not raw file contents or plaintext epoch
keys.

```mermaid
flowchart LR
    Device["User devices<br/>Desktop app + CLI"]
    HC["HybridCipher<br/>local encryption + device trust"]
    Cloud["Cloud coordination service<br/>ciphertext + metadata only"]

    Device --> HC
    HC --> Cloud
    Cloud --> HC
    HC --> Device
```

## How the Public Source Fits Together

This repository contains the public client-side source for the desktop app, the
bundled `hybridcipher` CLI, and the shared Rust crates they use. The server is
an external coordination system from this repo's point of view.

```mermaid
flowchart LR
    User["User"] --> Desktop["Desktop app"]
    User --> CLI["hybridcipher CLI"]
    Desktop --> Client["Shared Rust client engine"]
    CLI --> Client
    Client --> Local["Local crypto, trust state, device state"]
    Client --> Server["External HybridCipher server"]
```

At a high level:

1. A user interacts through the desktop app or the bundled CLI.
2. The shared client engine performs encryption, decryption, trust validation,
   and local state handling on the user device.
3. Only ciphertext, metadata, and encrypted coordination artifacts are sent to
   the external server.

For the deeper repo-level explanation, start with
[apps/desktop/architecture/README.md](apps/desktop/architecture/README.md).

## What This Repo Contains

Included here:

- `apps/desktop/` for the Tauri desktop app, frontend assets, legal notices,
  release metadata, icons, and the optional feedback API helper
- the Rust crates needed to build the desktop app and bundled CLI from source
- public rebuild tooling such as `scripts/macos/public_desktop_verify.sh`
- [docs/desktop/OPEN_SOURCE_VERIFY.md](docs/desktop/OPEN_SOURCE_VERIFY.md) for
  the public verification model and hash-comparison rules
- [LICENSE](LICENSE) for the repository-level licensing terms
- [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance

Not included here:

- the server-side and transparency-publishing components
- deployment and operations directories such as `config/`, `ops/`, `docker/`,
  and `k8s/`
- private planning notes and internal operational documentation

## Build Locally From Source

### General workspace checks

From the repository root:

```bash
cargo build
cargo test
```

### macOS prerequisites for desktop builds

The public desktop build flow is currently macOS-focused and expects:

- Xcode command line tools
- Rust stable plus the macOS target you want to build
- Node.js 18+ with `npm`
- `python3`

Example target setup:

```bash
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
```

### Reproducible unsigned macOS desktop build

If you want the supported public rebuild path, use the verification script:

```bash
MODE=silicon ./scripts/macos/public_desktop_verify.sh
MODE=full ./scripts/macos/public_desktop_verify.sh
```

Published verification values for the current source snapshot:

<!-- BEGIN GENERATED VERIFY HASHES -->
| Source ref | Target | Artifact | SHA-256 |
| --- | --- | --- | --- |
| `46d564b72e069442243bad5055ea009678efa6dd` | `aarch64-apple-darwin` | `HybridCipher_aarch64.unsigned.app.tar.gz` | `082d30e6f28a8ba33477d5f9e8f778e155f7d1cbc49188485a0904675b4f27e1` |
| `46d564b72e069442243bad5055ea009678efa6dd` | `x86_64-apple-darwin` | `HybridCipher_x86_64.unsigned.app.tar.gz` | `093c67fc00c07a4ee6e3cf2d31a4aeb1168e7b6a6bc23e08071cf8abb2082c06` |
<!-- END GENERATED VERIFY HASHES -->

That script:

- installs the desktop frontend dependencies
- builds the `hybridcipher` CLI for each requested target
- stages that CLI into `apps/desktop/src-tauri/resources/bin/`
- builds the unsigned desktop bundle
- writes deterministic `.tar.gz` and `.sha256` outputs for comparison

Read [docs/desktop/OPEN_SOURCE_VERIFY.md](docs/desktop/OPEN_SOURCE_VERIFY.md)
for what that build proves and which hashes to compare.

### Manual desktop build workflow

If you want to build the desktop app step by step instead of using the helper
script, use the same sequence the public build tooling expects:

```bash
cargo build --release --bin hybridcipher --target aarch64-apple-darwin
install -d apps/desktop/src-tauri/resources/bin
install -m 0755 \
  target/aarch64-apple-darwin/release/hybridcipher \
  apps/desktop/src-tauri/resources/bin/hybridcipher
cd apps/desktop
npm install
npx tauri build --target aarch64-apple-darwin
```

That manual flow stages the CLI into the app resources before packaging, which
matches the way `scripts/macos/public_desktop_verify.sh` prepares the bundle.

### Local desktop development

For local desktop development without packaging, point the app at a
workspace-built CLI explicitly:

```bash
cargo build --release --bin hybridcipher
export HYBRIDCIPHER_CLI_PATH="$PWD/target/release/hybridcipher"
cd apps/desktop
npm install
npx tauri dev
```

The app can also discover some workspace-built CLI outputs automatically, but
setting `HYBRIDCIPHER_CLI_PATH` keeps the local development path explicit.

## Verify a Published Release

Use the public verification flow when you want to reproduce the canonical
unsigned macOS app archive for a release snapshot and compare its SHA-256 hash:

```bash
MODE=silicon ./scripts/macos/public_desktop_verify.sh
```

The verification model, artifact names, and hash-comparison guidance live in
[docs/desktop/OPEN_SOURCE_VERIFY.md](docs/desktop/OPEN_SOURCE_VERIFY.md).

## Start Here

- Want to understand the public architecture:
  [apps/desktop/architecture/README.md](apps/desktop/architecture/README.md)
- Want the desktop app overview:
  [apps/desktop/README.md](apps/desktop/README.md)
- Want to build the desktop app from source:
  this [README.md](README.md)
- Want to verify a published release:
  [docs/desktop/OPEN_SOURCE_VERIFY.md](docs/desktop/OPEN_SOURCE_VERIFY.md)
- Want to contribute:
  [CONTRIBUTING.md](CONTRIBUTING.md)

## Contributing

If you want to help improve the public client surface, start with
[CONTRIBUTING.md](CONTRIBUTING.md). That guide points to the desktop, CLI, and
shared client layers that are present in this repository.
