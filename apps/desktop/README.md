# HybridCipher Desktop

HybridCipher Desktop is the Tauri-based desktop client for HybridCipher secure
file encryption, protected-folder coverage, device trust, recovery workflows,
and team file sharing.

This repository includes the frontend in `src/`, the Rust/Tauri shell in
`src-tauri/`, the packaged legal and release-note assets, the desktop icon set,
and the optional feedback API helper.

## Platform Scope

- The desktop app is configured for macOS, Windows, and Linux bundles.
- The public rebuild and verification scripts included in this repository are
  currently macOS-focused.
- On macOS, the installed desktop app can expose the bundled `hybridcipher`
  terminal command at `/usr/local/bin/hybridcipher`.

## Repository Layout

- `src/`: HTML, CSS, and JavaScript for the desktop UI
- `src-tauri/`: native shell, updater integration, IPC commands, packaging
  config, and app resources
- `src-tauri/resources/bin/`: build staging location for the bundled
  `hybridcipher` CLI resource used in packaged desktop builds
- `legal/`: bundled terms, privacy notice, and third-party notices
- `release-notes/`: updater release metadata consumed by the app
- `feedback-api/`: optional feedback submission service used by the desktop app

## First-Run Flow

1. Launch the app and review the bundled terms for the current release.
2. Register or log in to a HybridCipher server.
3. Add one or more protected folders.
4. Use Settings to review update status, coverage state, device trust, and
   recovery actions.

## Local Build Notes

- `src-tauri/tauri.conf.json` is the source of truth for the desktop bundle
  identifier, updater endpoint, packaging resources, and icon paths.
- `../../scripts/macos/public_desktop_verify.sh` is the supported public path
  for building unsigned macOS verification artifacts.
- `../../scripts/macos/local_desktop_release.sh` is the local macOS release
  builder for signed/notarized release work when the required signing
  environment is available.
- `npx tauri build` stages the bundled CLI resource into
  `src-tauri/resources/bin/` automatically when a workspace-built
  `target/<profile>/hybridcipher` binary (or `HYBRIDCIPHER_CLI_PATH`) is
  available.
- `npx tauri dev` can use a workspace-built CLI via `HYBRIDCIPHER_CLI_PATH`.

For the full local build commands and verification entrypoints, start with the
root [`README.md`](../../README.md).

## Related Public Docs

- Repository overview and local build commands:
  [`../../README.md`](../../README.md)
- Verification explainer:
  [`../../docs/desktop/OPEN_SOURCE_VERIFY.md`](../../docs/desktop/OPEN_SOURCE_VERIFY.md)
- Architecture explainer:
  [`architecture/README.md`](architecture/README.md)
- Contribution guide:
  [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)
- Feedback API:
  [`feedback-api/README.md`](feedback-api/README.md)
- Icon assets:
  [`src-tauri/icons/README.md`](src-tauri/icons/README.md)
- Tauri config:
  [`src-tauri/tauri.conf.json`](src-tauri/tauri.conf.json)
