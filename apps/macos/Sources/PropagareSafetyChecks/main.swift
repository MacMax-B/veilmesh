import Foundation
import PropagareSafety

@main
@MainActor
enum PropagareSafetyChecks {
  static func main() async throws {
    let singleNode = NetworkSafety(
      gate: .production,
      connectedNodes: 1,
      independentOperators: 1,
      requiredIndependentOperators: 5,
      hasAuditedOnionProvider: true,
      hasUniformCoverTraffic: true,
      hasSybilResourceProof: true
    )
    precondition(!singleNode.canClaimMetadataAnonymity, "one node claimed metadata anonymity")

    let bootstrap = NetworkSafety(
      gate: .testnet,
      connectedNodes: 1,
      independentOperators: 1,
      requiredIndependentOperators: 5,
      hasAuditedOnionProvider: false,
      hasUniformCoverTraffic: false,
      hasSybilResourceProof: false
    )
    precondition(bootstrap.canUseDirectBootstrap, "one verified testnet node could not bootstrap")
    precondition(bootstrap.canSend, "direct bootstrap did not enable testnet sending")
    precondition(!bootstrap.canClaimMetadataAnonymity, "direct bootstrap claimed anonymity")

    let complete = NetworkSafety(
      gate: .production,
      connectedNodes: 7,
      independentOperators: 5,
      requiredIndependentOperators: 5,
      hasAuditedOnionProvider: true,
      hasUniformCoverTraffic: true,
      hasSybilResourceProof: true
    )
    precondition(complete.canClaimMetadataAnonymity, "complete production gate remained locked")

    let client = SafetyLockedCoreClient()
    do {
      try await client.sendMessage(conversationID: UUID(), plaintext: "hello")
      fatalError("safety-locked core accepted a message")
    } catch CoreBoundaryError.productionProvidersUnavailable {
      // Expected.
    }

    do {
      try await client.sendMessage(conversationID: UUID(), plaintext: " \n")
      fatalError("safety-locked core accepted an empty message")
    } catch CoreBoundaryError.invalidMessage {
      // Expected.
    }

    print("Propagare macOS safety checks passed")
  }
}
