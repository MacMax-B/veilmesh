import SwiftUI

struct ContactsView: View {
  var body: some View {
    List {
      Section("Identity Directory") {
        Label(
          "Contact lookup remains unavailable", systemImage: "person.crop.circle.badge.questionmark"
        )
        Text(
          "A direct directory query would expose contact interest. Lookups must use the same constant-rate anonymous fetch path as messages."
        )
        .font(.callout)
        .foregroundStyle(.secondary)
      }
    }
    .scrollContentBackground(.hidden)
    .background(PropagareDesign.black)
    .navigationTitle("Contacts")
  }
}

struct SettingsView: View {
  let model: AppModel

  private var compactConversationList: Binding<Bool> {
    Binding(
      get: { model.compactConversationList },
      set: { model.compactConversationList = $0 }
    )
  }

  private var showsInspector: Binding<Bool> {
    Binding(
      get: { model.showsInspector },
      set: { model.showsInspector = $0 }
    )
  }

  var body: some View {
    TabView {
      Form {
        Section("Appearance") {
          Toggle("Compact conversation list", isOn: compactConversationList)
          Toggle("Show conversation inspector", isOn: showsInspector)
        }
        Section("Accessibility") {
          Text(
            "System controls automatically respect reduced transparency, increased contrast, and reduced motion."
          )
          .foregroundStyle(.secondary)
        }
      }
      .formStyle(.grouped)
      .tabItem { Label("General", systemImage: "gearshape") }

      Form {
        Section("Production Gate") {
          LabeledContent("Messaging", value: "Locked")
          LabeledContent("Metadata anonymity", value: "Not active")
          LabeledContent("Core secrets exposed to UI", value: "Never")
        }
      }
      .formStyle(.grouped)
      .tabItem { Label("Security", systemImage: "lock.shield") }
    }
    .padding(12)
    .preferredColorScheme(.dark)
  }
}
