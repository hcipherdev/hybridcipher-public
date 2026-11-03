# HybridCipher Desktop Open Source Verification

This repository publishes the client-side source used to reproduce canonical
unsigned HybridCipher desktop build artifacts for a release snapshot.

## Platform app versions

Edit the app version only in `apps/desktop/src-tauri/tauri.windows.conf.json`
for Windows or `apps/desktop/src-tauri/tauri.macos.conf.json` for macOS.
Their release versions advance independently. Build scripts, public verifiers,
installer metadata, and the running app use the corresponding platform config.

The shared desktop `Cargo.toml` and `Cargo.lock` contain crate metadata, not
the Windows or macOS app release version. Builds do not synchronize these
versions or rewrite the shared `tauri.conf.json`. Missing or invalid platform
versions stop the build. `VERSION_OVERRIDE` may only forward the same macOS
version; conflicting overrides are rejected. Store and sparse MSIX identity
revisions remain separate from the Windows app version.

## What this proves

- The desktop app and bundled `hybridcipher` CLI can be rebuilt from the
  published source snapshot.
- Reviewers can inspect the source used for that release snapshot.
- Reviewers can reproduce the canonical unsigned macOS `.app` archive or
  Windows NSIS installer and compare its SHA-256 hash to the published value.

## What this does not prove

- It does not guarantee byte-for-byte reproduction of final notarized macOS
  `.pkg`, Authenticode-signed Windows installers, or signed updater artifacts.
- Apple signing, notarization, stapling, Windows Authenticode signing, and
  release packaging remain separate distribution layers on top of the
  canonical unsigned build.

## Prerequisites

- macOS with Xcode command line tools for macOS verification
- Windows with Visual Studio Build Tools and the Windows SDK for Windows
  verification
- `rustup`, set up as described in [Set up Rust](#set-up-rust)
- Node.js with `npm`
- `python3`

## Set up Rust

The published hashes were built with the Rust version pinned in
`rust-toolchain.toml`. A different compiler version produces different binaries,
so it must match. `rustup` reads that file and selects the pinned version
automatically. Other installations, such as Homebrew's `rust` or a Linux
distribution package, ignore it.

Find out what you have:

```bash
rustup --version
```

**If that command is not found** (no Rust yet, or Rust from Homebrew or a
package manager), install `rustup`.

On macOS:

```bash
brew uninstall rust   # only if Rust was installed with Homebrew
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

On Windows, download and run `rustup-init.exe` from <https://rustup.rs>, accept
the default `x86_64-pc-windows-msvc` host, then open a new PowerShell window.

**If you already use `rustup`**, keep your setup. Your default toolchain does not
change; `rustup` switches to the pinned version only inside this repository. Run
`rustup self update` if your `rustup` is older than 1.28.

Then, from the repository root, install the pinned toolchain with its targets and
confirm that it is the one in use:

```bash
rustup toolchain install
rustc --version
```

`rustc --version` must print the version from `rust-toolchain.toml`, with no
"(Homebrew)" suffix. If it prints something else, another Rust installation
comes first in your `PATH`. Check with `which cargo` on macOS or
`Get-Command cargo` on Windows; the `rustup` copy is in `~/.cargo/bin` (on
Windows, `%USERPROFILE%\.cargo\bin`). Either remove the other installation or
put the `rustup` directory first in `PATH`, then open a new terminal.

The macOS verification script also warns when the active compiler does not match
the pinned version.

## Canonical verification build

Build the canonical unsigned artifact locally:

```bash
MODE=silicon ./scripts/macos/public_desktop_verify.sh
MODE=full ./scripts/macos/public_desktop_verify.sh
```

The macOS verifier uses the shared build and File Provider validation functions
in `scripts/macos/desktop_build_common.sh`. It does not load the release env file
or require Developer ID, notarization, or updater-signing credentials. Local
verification bundles use ad-hoc signatures so their assembled runtime can be
checked before archiving.

The same shared script also supports standalone source or bundle checks:

```bash
bash scripts/macos/desktop_build_common.sh --validate-file-provider
bash scripts/macos/desktop_build_common.sh --validate-file-provider /path/to/HybridCipher.app
```

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\winos\public_desktop_verify.ps1
```

This produces one canonical unsigned archive per target architecture in the
desktop bundle output directory:

- `target/aarch64-apple-darwin/release/bundle/macos/HybridCipher_aarch64.unsigned.app.tar.gz`
- `target/x86_64-apple-darwin/release/bundle/macos/HybridCipher_x86_64.unsigned.app.tar.gz`
- `target/x86_64-pc-windows-msvc/release/bundle/nsis/HybridCipher_<version>_x64-setup.exe`
- matching `.sha256` files beside each archive

## Team verification keys

Desktop and CLI builds embed the public keys that verify Team licenses. The
published list is in `apps/desktop/team-verification-keys.txt`, and the
verification scripts use it automatically, so no extra setup is needed.

These are public keys only. Setting `HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS` to a
different value changes the compiled binaries, so the result will not match
the published hashes; the scripts print a warning when that happens. Release
builds are required to embed exactly the published list.

## Hash comparison

Compare the locally generated SHA-256 with the published release manifest for
the same source snapshot:

```bash
cat target/aarch64-apple-darwin/release/bundle/macos/HybridCipher_aarch64.unsigned.app.tar.gz.sha256
```

On Windows:

```powershell
Get-Content target\x86_64-pc-windows-msvc\release\bundle\nsis\HybridCipher_<version>_x64-setup.exe.sha256
```

Users should compare the canonical unsigned artifact hash, not the notarized
macOS `.pkg` hash, Authenticode-signed Windows installer hash, or signed
updater package hash.

The release manifest should identify both:

- the public source snapshot or source ref that was published
- the canonical unsigned archive hash for each target architecture

## Related docs

- Build overview: `../../README.md`
- Desktop app overview: `../../apps/desktop/README.md`
- Desktop architecture: `../../apps/desktop/architecture/README.md`

## Public export safeguards

The public desktop export excludes the feedback API and the shared source catalog
`apps/desktop/release-notes/releases.json`. Windows and macOS keep their own
release-note catalogs; signed bundles may still name the selected catalog
`release-notes/releases.json` inside the installed application.

Both exporters exclude credential files, environment files, logs, and generated
directories at any depth. They validate a temporary export before replacing the
destination. Recognizable credentials or symlinks stop the export; diagnostics
show file paths, line numbers, and rule names without printing secret values.
