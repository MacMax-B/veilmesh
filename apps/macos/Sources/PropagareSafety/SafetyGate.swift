import Foundation

public struct NetworkSafety: Equatable, Sendable {
  public enum Gate: Equatable, Sendable {
    case locked
    case testnet
    case production
  }

  public let gate: Gate
  public let connectedNodes: Int
  public let independentOperators: Int
  public let requiredIndependentOperators: Int
  public let hasAuditedOnionProvider: Bool
  public let hasUniformCoverTraffic: Bool
  public let hasSybilResourceProof: Bool

  public init(
    gate: Gate,
    connectedNodes: Int,
    independentOperators: Int,
    requiredIndependentOperators: Int,
    hasAuditedOnionProvider: Bool,
    hasUniformCoverTraffic: Bool,
    hasSybilResourceProof: Bool
  ) {
    self.gate = gate
    self.connectedNodes = connectedNodes
    self.independentOperators = independentOperators
    self.requiredIndependentOperators = requiredIndependentOperators
    self.hasAuditedOnionProvider = hasAuditedOnionProvider
    self.hasUniformCoverTraffic = hasUniformCoverTraffic
    self.hasSybilResourceProof = hasSybilResourceProof
  }

  public var canClaimMetadataAnonymity: Bool {
    gate == .production && independentOperators >= requiredIndependentOperators
      && hasAuditedOnionProvider && hasUniformCoverTraffic && hasSybilResourceProof
  }

  public var canUseDirectBootstrap: Bool {
    gate == .testnet && connectedNodes >= 1
  }

  public var canSend: Bool {
    canUseDirectBootstrap || canClaimMetadataAnonymity
  }

  public static let locked = NetworkSafety(
    gate: .locked,
    connectedNodes: 0,
    independentOperators: 0,
    requiredIndependentOperators: 5,
    hasAuditedOnionProvider: false,
    hasUniformCoverTraffic: false,
    hasSybilResourceProof: false
  )
}

public enum CoreBoundaryError: LocalizedError, Equatable, Sendable {
  case productionProvidersUnavailable
  case invalidMessage

  public var errorDescription: String? {
    switch self {
    case .productionProvidersUnavailable:
      "Sending is locked until the audited Ratchet, Onion/SURB, and OS-vault providers are available."
    case .invalidMessage:
      "The message is empty or exceeds the client limit."
    }
  }
}

/// Narrow UI boundary. Deliberately contains no key, route-tag, delete-token,
/// receipt, raw packet, or unverified network-response type.
@MainActor
public protocol PropagareCoreClient: AnyObject {
  func currentNetworkSafety() async -> NetworkSafety
  func sendMessage(conversationID: UUID, plaintext: String) async throws
}

@MainActor
public final class SafetyLockedCoreClient: PropagareCoreClient {
  public init() {}

  public func currentNetworkSafety() async -> NetworkSafety {
    .locked
  }

  public func sendMessage(conversationID _: UUID, plaintext: String) async throws {
    let message = plaintext.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !message.isEmpty, message.utf8.count <= 192 * 1_024 else {
      throw CoreBoundaryError.invalidMessage
    }
    throw CoreBoundaryError.productionProvidersUnavailable
  }
}
