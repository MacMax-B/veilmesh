import SwiftUI

struct ConversationListView: View {
  let model: AppModel

  private var searchText: Binding<String> {
    Binding(
      get: { model.searchText },
      set: { model.searchText = $0 }
    )
  }

  var body: some View {
    ScrollView {
      LazyVStack(spacing: 4) {
        ForEach(model.filteredConversations) { conversation in
          let isSelected = model.selectedConversationID == conversation.id
          Button {
            model.selectedConversationID = conversation.id
          } label: {
            ConversationRow(
              conversation: conversation,
              compact: model.compactConversationList,
              isSelected: isSelected
            )
          }
          .buttonStyle(.plain)
          .accessibilityAddTraits(isSelected ? .isSelected : [])
        }
      }
      .padding(8)
    }
    .background(PropagareDesign.black)
    .searchable(text: searchText, placement: .sidebar, prompt: "Search conversations")
    .navigationTitle("Messages")
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
  let isSelected: Bool

  var body: some View {
    HStack(spacing: 12) {
      AvatarView(
        initials: conversation.initials,
        color: conversation.color,
        size: compact ? 36 : 44,
        isInverted: isSelected
      )
      VStack(alignment: .leading, spacing: 4) {
        HStack(spacing: 5) {
          Text(conversation.title)
            .font(.body.weight(.semibold))
            .lineLimit(1)
          if conversation.isVerified {
            Image(systemName: "checkmark.seal.fill")
              .font(.caption)
              .foregroundStyle(isSelected ? PropagareDesign.black : PropagareDesign.white)
              .accessibilityLabel("Verified contact")
          }
          Spacer(minLength: 4)
          if conversation.unreadCount > 0 {
            Text("\(conversation.unreadCount)")
              .font(.caption2.bold())
              .foregroundStyle(isSelected ? PropagareDesign.white : PropagareDesign.black)
              .padding(.horizontal, 7)
              .padding(.vertical, 3)
              .background(
                isSelected ? PropagareDesign.black : PropagareDesign.white,
                in: Capsule()
              )
              .accessibilityLabel("\(conversation.unreadCount) unread messages")
          }
        }
        if !compact {
          Text(conversation.subtitle)
            .font(.callout)
            .foregroundStyle(
              isSelected ? PropagareDesign.black.opacity(0.6) : PropagareDesign.muted
            )
            .lineLimit(2)
        }
      }
    }
    .foregroundStyle(isSelected ? PropagareDesign.black : PropagareDesign.white)
    .padding(.horizontal, 10)
    .padding(.vertical, compact ? 7 : 10)
    .background(
      isSelected ? PropagareDesign.white : PropagareDesign.black,
      in: RoundedRectangle(cornerRadius: 14, style: .continuous)
    )
    .contentShape(Rectangle())
  }
}
