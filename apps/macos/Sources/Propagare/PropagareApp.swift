import PropagareSafety
import SwiftUI

@main
@MainActor
struct PropagareApp: App {
  private let model = AppModel(core: SafetyLockedCoreClient())

  var body: some Scene {
    WindowGroup {
      AppShellView(model: model)
        .frame(minWidth: 940, minHeight: 620)
        .preferredColorScheme(.dark)
        .tint(PropagareDesign.white)
    }
    .defaultSize(width: 1_240, height: 780)
    .windowToolbarStyle(.unifiedCompact)
    .commands {
      CommandGroup(after: .sidebar) {
        Button("Show Network Safety") {
          model.selection = .network
        }
        .keyboardShortcut("n", modifiers: [.command, .shift])
      }
    }

    Settings {
      SettingsView(model: model)
        .frame(width: 560, height: 420)
        .preferredColorScheme(.dark)
        .tint(PropagareDesign.white)
    }
  }
}
