# Contributing to HybridCipher

This repository contains the public client-side HybridCipher code: the desktop
app, bundled `hybridcipher` CLI, and the shared Rust client stack those entry
points use.

Some HybridCipher components live outside this repository, including the server,
deployment assets, and operations tooling. Please scope contributions to the
code and documentation that are present here.

## Good Contributions for This Repo

- desktop UX, packaging, and documentation improvements under `apps/desktop/`
- CLI and shared-client fixes under `crates/cli/` and `crates/client/`
- crypto, coverage, Merkle, and local security improvements in the published
  Rust crates
- public build reproducibility improvements
- documentation that helps evaluators and contributors understand the public
  client surface

## Before You Start

- Read the root `README.md` for the repository overview and local build entry
  points.
- Read `apps/desktop/architecture/README.md` for the client-side architecture
  exposed here.
- Check existing issues or discussions in the public repo before opening a new
  one:
  - Issues: <https://github.com/HybridCipher/hybridcipher-public/issues>
  - Discussions: <https://github.com/HybridCipher/hybridcipher-public/discussions>

## Development Setup

### Prerequisites

- Rust stable toolchain
- Git
- Node.js 18+ and npm for the desktop frontend
- `xcrun` on macOS if you want to run the public desktop verification build

### Useful Commands

```bash
# Build the public workspace
cargo build

# Run the public Rust tests
cargo test

# Build the desktop verification artifacts on macOS
./scripts/macos/public_desktop_verify.sh
```

For the full desktop build and local development commands, use the root
`README.md` as the primary entry point.

## Contribution Expectations

- Keep pull requests focused and explain user-visible impact clearly.
- Update docs when behavior or contributor workflow changes.
- Follow existing Rust and frontend patterns already used in the repo.
- Do not commit secrets, private keys, or private operational material.
- Use Conventional Commits for commit messages when practical.

Examples:

```text
docs(readme): clarify public repo trust model
fix(desktop): remove stale public build warning
chore(oss): tighten public sync filters
```

## Security Reporting

Do not open public issues for security vulnerabilities.

Report security concerns to:

- <mailto:security@hybridcipher.com>

Include enough detail to reproduce or assess the issue safely.

## Questions

If you are unsure whether a change belongs in this repository:

- open an issue in the public repo
- start a GitHub Discussion
- or email <mailto:contact@hybridcipher.com>

Thank you for improving HybridCipher.
