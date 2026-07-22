import Foundation
import Observation
import PropagareSafety

@MainActor
@Observable
final class AppModel {
  var selection: SidebarSelection = .chats
  var selectedConversationID: Conversation.ID?
  var conversations: [Conversation]
  var searchText = ""
  var draft = ""
  var networkSafety: NetworkSafety = .locked
  var composerError: String?
  var showsInspector = true
  var compactConversationList = false

  private let core: any PropagareCoreClient

  init(
    core: any PropagareCoreClient,
    conversations: [Conversation] = SampleData.conversations
  ) {
    self.core = core
    self.conversations = conversations
    selectedConversationID = conversations.first?.id
  }

  var filteredConversations: [Conversation] {
    let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !query.isEmpty else { return conversations }
    return conversations.filter {
      $0.title.localizedCaseInsensitiveContains(query)
        || $0.subtitle.localizedCaseInsensitiveContains(query)
    }
  }

  var selectedConversation: Conversation? {
    guard let selectedConversationID else { return nil }
    return conversations.first { $0.id == selectedConversationID }
  }

  var canSend: Bool {
    networkSafety.canSend && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
  }

  func refreshSafety() async {
    networkSafety = await core.currentNetworkSafety()
  }

  func sendDraft() async {
    guard let selectedConversationID else { return }
    do {
      try await core.sendMessage(conversationID: selectedConversationID, plaintext: draft)
      draft = ""
      composerError = nil
    } catch {
      composerError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }
  }
}
