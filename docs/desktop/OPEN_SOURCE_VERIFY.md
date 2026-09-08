# HybridCipher Desktop Open Source Verification

This repository publishes the client-side source used to reproduce canonical
unsigned HybridCipher desktop build artifacts for a release snapshot.

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
- Rust stable toolchain with the target you want to verify
- Node.js with `npm`
- `python3`

Example target setup:

```bash
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
```

Windows target setup:

```powershell
rustup target add x86_64-pc-windows-msvc
```

## Canonical verification build

Build the canonical unsigned artifact locally:

```bash
MODE=silicon ./scripts/macos/public_desktop_verify.sh
MODE=full ./scripts/macos/public_desktop_verify.sh
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
