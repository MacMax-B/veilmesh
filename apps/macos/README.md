# Propagare for macOS

Native SwiftUI shell for the Propagare client core. It uses standard macOS
navigation and toolbar components so current macOS releases provide the native
Liquid Glass appearance automatically. Custom glass is limited to interactive
controls and the left navigation group. The messenger is deliberately
monochrome: a true `#000000` canvas, `#FFFFFF` primary content, and opacity-only
secondary hierarchy. It does not rely on an accent color to communicate safety
state.

## Build

Build with the selected Xcode toolchain:

```bash
cd apps/macos
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift build
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift run PropagareSafetyChecks
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift run Propagare
```

Open `Package.swift` in Xcode for previews, accessibility inspection,
XCTest UI coverage, signing, notarization, and distribution packaging. The
standalone safety checks avoid an XCTest dependency and therefore also run with
Apple's Command Line Tools-only installation.

The visual system follows Apple's guidance to keep Liquid Glass in the
navigation and interactive layer while preserving a clear content hierarchy:

- <https://developer.apple.com/documentation/TechnologyOverviews/adopting-liquid-glass>
- <https://developer.apple.com/design/human-interface-guidelines/materials>

## Security boundary

This branch intentionally ships with `SafetyLockedCoreClient`. The UI cannot
send messages until the planned versioned local Core service/FFI implements the
DTOs in `docs/FRONTEND-API.md` and the required audited Ratchet, Onion/SURB, and
OS-vault providers are present. The UI never receives private keys, delete
capabilities, route tags, or raw network responses.

The included sample conversations are visual fixture data only. Do not market
or distribute this shell as a production messenger.
