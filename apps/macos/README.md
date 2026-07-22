# Propagare for macOS

Native SwiftUI shell for the Propagare client core. It uses standard macOS
navigation and toolbar components so current macOS releases provide the native
Liquid Glass appearance automatically. Custom glass is limited to interactive
controls; content surfaces use ordinary materials.

## Build

The command-line Swift toolchain is enough for compile and unit-test checks:

```bash
cd apps/macos
swift build
swift run PropagareSafetyChecks
swift run Propagare
```

Open `Package.swift` in the latest Xcode for previews, accessibility inspection,
XCTest UI coverage, signing, notarization, and distribution packaging. The
standalone safety checks avoid an XCTest dependency and therefore also run with
Apple's Command Line Tools-only installation.

## Security boundary

This branch intentionally ships with `SafetyLockedCoreClient`. The UI cannot
send messages until the planned versioned local Core service/FFI implements the
DTOs in `docs/FRONTEND-API.md` and the required audited Ratchet, Onion/SURB, and
OS-vault providers are present. The UI never receives private keys, delete
capabilities, route tags, or raw network responses.

The included sample conversations are visual fixture data only. Do not market
or distribute this shell as a production messenger.
