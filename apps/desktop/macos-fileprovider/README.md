# HybridCipher macOS File Provider

This directory is the source-owned macOS File Provider implementation for the desktop app.

The Swift extension is intentionally thin:

- Apple File Provider callbacks stay in Swift.
- HybridCipher inventory, identity, hydration, mutation replay, conflicts, and recovery stay in Rust.
- Swift and Rust communicate over a Unix socket using the JSON protocol defined in `crates/macos-file-provider`. The containing app and extension share app-group entitlements, and the socket file uses the shared app-group container at `~/Library/Group Containers/<team>.group.com.hybridcipher.macOS/<root>.sock`. That container is the only place the sandboxed extension may connect to, so there is no other location. Its path can be longer than the 104-byte `sun_path` field (a user name over 9 characters is enough), so both sides pass an oversized `sockaddr_un` whose `sun_len` covers the whole path, which the kernel accepts up to 255 bytes (`crates/macos-file-provider/src/long_socket.rs`, `ProviderBridgeClient.socketAddress`). The host also reports whether the extension itself has connected (`extension_connected`), because a reachable listener alone doesn't prove Finder can reach it.

Bundle identifiers:

- Containing app: `com.hybridcipher.app`
- Extension: `com.hybridcipher.app.HybridCipherFileProvider`
- App group: `group.com.hybridcipher.macOS`

The `.appex` must be built into `HybridCipher.app/Contents/PlugIns/HybridCipherFileProvider.appex` and signed with the same app-group entitlement as the containing app. Release builds must not include `com.apple.developer.fileprovider.testing-mode`.
