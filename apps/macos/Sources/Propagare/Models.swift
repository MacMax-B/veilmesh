import Foundation
import SwiftUI

enum SidebarSelection: String, CaseIterable, Identifiable, Sendable {
  case chats
  case contacts
  case network

  var id: String { rawValue }

  var title: LocalizedStringKey {
    switch self {
    case .chats: "Chats"
    case .contacts: "Contacts"
    case .network: "Network Safety"
    }
  }

  var symbol: String {
    switch self {
    case .chats: "bubble.left.and.bubble.right.fill"
    case .contacts: "person.2.fill"
    case .network: "network.badge.shield.half.filled"
    }
  }
}

struct Conversation: Identifiable, Hashable, Sendable {
  let id: UUID
  let title: String
  let subtitle: String
  let initials: String
  let color: AccentColor
  let unreadCount: Int
  let isVerified: Bool
  let messages: [ChatMessage]
}

struct ChatMessage: Identifiable, Hashable, Sendable {
  enum Direction: Sendable {
    case incoming
    case outgoing
    case system
  }

  enum DeliveryState: Sendable {
    case delivered
    case pending
    case blocked
  }

  let id: UUID
  let direction: Direction
  let body: String
  let timestamp: Date
  let delivery: DeliveryState
}

enum AccentColor: String, CaseIterable, Sendable {
  case cyan
  case violet
  case coral
  case mint
  case blue

  var color: Color {
    switch self {
    case .cyan: .cyan
    case .violet: .purple
    case .coral: .orange
    case .mint: .mint
    case .blue: .blue
    }
  }
}

enum SampleData {
  static let conversations: [Conversation] = [
    Conversation(
      id: UUID(uuidString: "86CFF12A-DF29-461E-A5FE-A73120EB2910")!,
      title: "Mira",
      subtitle: "The transport is still safety-locked.",
      initials: "MI",
      color: .violet,
      unreadCount: 2,
      isVerified: true,
      messages: [
        ChatMessage(
          id: UUID(uuidString: "EA5B179B-95E2-4598-ABBD-A110725748EE")!,
          direction: .system,
          body: "Sample conversation · no network data",
          timestamp: Date(timeIntervalSince1970: 1_774_200_000),
          delivery: .delivered
        ),
        ChatMessage(
          id: UUID(uuidString: "882A3AC0-F326-4D93-92A8-BA11B25D43CC")!,
          direction: .incoming,
          body: "This interface stays locked until the audited mix provider is connected.",
          timestamp: Date(timeIntervalSince1970: 1_774_200_300),
          delivery: .delivered
        ),
        ChatMessage(
          id: UUID(uuidString: "A9D3B76E-D2E8-4A1C-9A75-03B0483ED1C7")!,
          direction: .outgoing,
          body: "Good. A direct HTTPS fallback must never pretend to be anonymous.",
          timestamp: Date(timeIntervalSince1970: 1_774_200_480),
          delivery: .delivered
        ),
      ]
    ),
    Conversation(
      id: UUID(uuidString: "5AB2F5D5-E6BC-410C-8F5B-B11FF002F366")!,
      title: "Design Circle",
      subtitle: "Liquid Glass, used with restraint.",
      initials: "DC",
      color: .cyan,
      unreadCount: 0,
      isVerified: true,
      messages: []
    ),
    Conversation(
      id: UUID(uuidString: "25F84BFD-BA24-46AE-A307-CA1238779F57")!,
      title: "Node Operators",
      subtitle: "Five independent operators required.",
      initials: "NO",
      color: .mint,
      unreadCount: 0,
      isVerified: false,
      messages: []
    ),
  ]
}
