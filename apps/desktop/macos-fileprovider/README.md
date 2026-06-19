# HybridCipher macOS File Provider

This directory is the source-owned macOS File Provider implementation for the desktop app.

The Swift extension is intentionally thin:

- Apple File Provider callbacks stay in Swift.
- HybridCipher inventory, identity, hydration, mutation replay, conflicts, and recovery stay in Rust.
- Swift and Rust communicate over a Unix socket using the JSON protocol defined in `crates/macos-file-provider`. The containing app and extension share app-group entitlements, and the socket file uses the shared app-group container at `~/Library/Group Containers/<team>.group.com.hybridcipher.macOS/s/<root>.sock`. The filename is shortened to stay under macOS `SUN_LEN`; `/tmp/hc-fp/<root>.sock` is only a fallback when the app-group path is unavailable or too long.

Bundle identifiers:

- Containing app: `com.hybridcipher.app`
- Extension: `com.hybridcipher.app.HybridCipherFileProvider`
- App group: `group.com.hybridcipher.macOS`

The `.appex` must be built into `HybridCipher.app/Contents/PlugIns/HybridCipherFileProvider.appex` and signed with the same app-group entitlement as the containing app. Release builds must not include `com.apple.developer.fileprovider.testing-mode`.
