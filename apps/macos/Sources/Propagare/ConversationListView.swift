import SwiftUI

struct ConversationListView: View {
  let model: AppModel

  private var selectedConversation: Binding<Conversation.ID?> {
    Binding(
      get: { model.selectedConversationID },
      set: { model.selectedConversationID = $0 }
    )
  }

  private var searchText: Binding<String> {
    Binding(
      get: { model.searchText },
      set: { model.searchText = $0 }
    )
  }

  var body: some View {
    List(model.filteredConversations, selection: selectedConversation) { conversation in
      ConversationRow(conversation: conversation, compact: model.compactConversationList)
        .tag(conversation.id)
    }
    .searchable(text: searchText, placement: .sidebar, prompt: "Search conversations")
    .navigationTitle("Chats")
    .toolbar {
      ToolbarItem {
        Button {
          model.composerError = "Creating conversations requires the production Core service."
        } label: {
          Label("New Message", systemImage: "square.and.pencil")
        }
        .help("New Message")
        .accessibilityLabel("New Message")
      }
    }
    .overlay {
      if model.filteredConversations.isEmpty {
        ContentUnavailableView.search(text: model.searchText)
      }
    }
  }
}

private struct ConversationRow: View {
  let conversation: Conversation
  let compact: Bool

  var body: some View {
    HStack(spacing: 12) {
      AvatarView(
        initials: conversation.initials,
        color: conversation.color,
        size: compact ? 36 : 44
      )
      VStack(alignment: .leading, spacing: 4) {
        HStack(spacing: 5) {
          Text(conversation.title)
            .font(.body.weight(.semibold))
            .lineLimit(1)
          if conversation.isVerified {
            Image(systemName: "checkmark.seal.fill")
              .font(.caption)
              .foregroundStyle(.cyan)
              .accessibilityLabel("Verified contact")
          }
          Spacer(minLength: 4)
          if conversation.unreadCount > 0 {
            Text("\(conversation.unreadCount)")
              .font(.caption2.bold())
              .foregroundStyle(.white)
              .padding(.horizontal, 7)
              .padding(.vertical, 3)
              .background(.blue, in: Capsule())
              .accessibilityLabel("\(conversation.unreadCount) unread messages")
          }
        }
        if !compact {
          Text(conversation.subtitle)
            .font(.callout)
            .foregroundStyle(.secondary)
            .lineLimit(2)
        }
      }
    }
    .padding(.vertical, compact ? 3 : 7)
  }
}
