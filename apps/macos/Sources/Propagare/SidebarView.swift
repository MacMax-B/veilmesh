import SwiftUI

struct SidebarView: View {
  let model: AppModel

  private var selection: Binding<SidebarSelection?> {
    Binding(
      get: { model.selection },
      set: { if let value = $0 { model.selection = value } }
    )
  }

  var body: some View {
    List(selection: selection) {
      Section("Propagare") {
        ForEach(SidebarSelection.allCases) { item in
          Label(item.title, systemImage: item.symbol)
            .tag(item)
        }
      }

      Section("Status") {
        HStack(spacing: 10) {
          Image(systemName: "lock.trianglebadge.exclamationmark.fill")
            .foregroundStyle(.orange)
          VStack(alignment: .leading, spacing: 2) {
            Text("Security Preview")
              .font(.callout.weight(.semibold))
            Text("Sending is safety-locked")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
        }
        .accessibilityElement(children: .combine)
      }
    }
    .listStyle(.sidebar)
    .safeAreaInset(edge: .bottom) {
      HStack(spacing: 10) {
        AvatarView(initials: "EN", color: .blue, size: 34)
        VStack(alignment: .leading, spacing: 1) {
          Text("Local Preview")
            .font(.callout.weight(.semibold))
          Text("No keys loaded")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        Spacer()
        Image(systemName: "gearshape")
          .foregroundStyle(.secondary)
      }
      .padding(12)
    }
    .navigationTitle("Propagare")
  }
}
