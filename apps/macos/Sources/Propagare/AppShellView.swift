import SwiftUI

struct AppShellView: View {
  let model: AppModel

  var body: some View {
    NavigationSplitView {
      SidebarView(model: model)
        .navigationSplitViewColumnWidth(min: 210, ideal: 236, max: 280)
    } content: {
      switch model.selection {
      case .chats:
        ConversationListView(model: model)
          .navigationSplitViewColumnWidth(min: 280, ideal: 330, max: 410)
      case .contacts:
        ContactsView()
          .navigationSplitViewColumnWidth(min: 320, ideal: 380, max: 460)
      case .network:
        NetworkSummaryListView(safety: model.networkSafety)
          .navigationSplitViewColumnWidth(min: 320, ideal: 390, max: 460)
      }
    } detail: {
      detail
    }
    .navigationSplitViewStyle(.balanced)
    .task {
      await model.refreshSafety()
    }
  }

  @ViewBuilder
  private var detail: some View {
    switch model.selection {
    case .chats:
      if let conversation = model.selectedConversation {
        ConversationDetailView(model: model, conversation: conversation)
      } else {
        ContentUnavailableView(
          "No Conversation Selected",
          systemImage: "bubble.left.and.bubble.right",
          description: Text("Choose a conversation from the list.")
        )
      }
    case .contacts:
      ContentUnavailableView(
        "Select a Contact",
        systemImage: "person.crop.circle.badge.checkmark",
        description: Text(
          "Verified ENIG contacts will appear here after the Core service is connected.")
      )
    case .network:
      NetworkSafetyView(safety: model.networkSafety)
    }
  }
}
