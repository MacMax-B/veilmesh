import PropagareSafety
import SwiftUI

struct NetworkSummaryListView: View {
  let safety: NetworkSafety

  var body: some View {
    List {
      Section("Release Gate") {
        if safety.canClaimMetadataAnonymity {
          Label("Full mix active", systemImage: "checkmark.shield.fill")
            .foregroundStyle(.green)
        } else if safety.canUseDirectBootstrap {
          Label("Direct bootstrap · metadata visible", systemImage: "exclamationmark.shield.fill")
            .foregroundStyle(.orange)
        } else {
          Label("Production transport locked", systemImage: "lock.fill")
            .foregroundStyle(.orange)
        }
      }
      Section("Topology") {
        LabeledContent("Connected nodes", value: "\(safety.connectedNodes)")
        LabeledContent("Independent operators", value: "\(safety.independentOperators)")
        LabeledContent("Required operators", value: "\(safety.requiredIndependentOperators)")
      }
      Section("Providers") {
        GateRow(title: "Audited Onion / SURB", complete: safety.hasAuditedOnionProvider)
        GateRow(title: "Uniform cover traffic", complete: safety.hasUniformCoverTraffic)
        GateRow(title: "Sybil resource proof", complete: safety.hasSybilResourceProof)
      }
    }
    .navigationTitle("Network Safety")
  }
}

struct NetworkSafetyView: View {
  let safety: NetworkSafety

  var body: some View {
    ZStack {
      PropagareDesign.backdrop
        .ignoresSafeArea()

      ScrollView {
        VStack(alignment: .leading, spacing: 24) {
          HStack(alignment: .top, spacing: 18) {
            Image(systemName: "network.badge.shield.half.filled")
              .font(.system(size: 44, weight: .semibold))
              .foregroundStyle(.cyan)
            VStack(alignment: .leading, spacing: 7) {
              Text("Network Safety Gate")
                .font(.largeTitle.bold())
              Text(
                "Propagare fails closed until the complete metadata-protection path is independently verified."
              )
              .font(.title3)
              .foregroundStyle(.secondary)
            }
          }

          LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 14)], spacing: 14) {
            SafetyCard(
              title: "Independent Operators",
              value: "\(safety.independentOperators) / \(safety.requiredIndependentOperators)",
              symbol: "building.2.crop.circle",
              complete: safety.independentOperators >= safety.requiredIndependentOperators
            )
            SafetyCard(
              title: "Audited Onion Provider",
              value: safety.hasAuditedOnionProvider ? "Verified" : "Missing",
              symbol: "seal",
              complete: safety.hasAuditedOnionProvider
            )
            SafetyCard(
              title: "Uniform Cover Traffic",
              value: safety.hasUniformCoverTraffic ? "Active" : "Not connected",
              symbol: "waveform.path.ecg.rectangle",
              complete: safety.hasUniformCoverTraffic
            )
            SafetyCard(
              title: "Sybil Resource Proof",
              value: safety.hasSybilResourceProof ? "Verified" : "Missing",
              symbol: "point.3.connected.trianglepath.dotted",
              complete: safety.hasSybilResourceProof
            )
          }

          VStack(alignment: .leading, spacing: 10) {
            Label("Why one node is not enough", systemImage: "exclamationmark.shield.fill")
              .font(.headline)
              .foregroundStyle(.orange)
            Text(
              "If the same operator observes entry and exit traffic, timing and volume can reveal who communicates with whom. Encryption protects content, not that relationship. The client therefore keeps sending disabled instead of falling back to direct HTTPS."
            )
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
          }
          .padding(18)
          .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

          VStack(alignment: .leading, spacing: 10) {
            Label("Automatic upgrade", systemImage: "arrow.up.forward.circle.fill")
              .font(.headline)
              .foregroundStyle(.cyan)
            Text(
              "A test network may send through one verified node in direct bootstrap mode. When the audited scheduler and seven diverse Full Nodes are available, the Core selects the 3-mix + courier + 3-replica route automatically. A stored Full Mix requirement never downgrades."
            )
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
          }
          .padding(18)
          .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        }
        .padding(28)
        .frame(maxWidth: 980)
        .frame(maxWidth: .infinity)
      }
    }
    .navigationTitle("Network Safety")
  }
}

private struct GateRow: View {
  let title: LocalizedStringKey
  let complete: Bool

  var body: some View {
    Label(title, systemImage: complete ? "checkmark.circle.fill" : "xmark.circle.fill")
      .foregroundStyle(complete ? .green : .orange)
  }
}

private struct SafetyCard: View {
  let title: LocalizedStringKey
  let value: String
  let symbol: String
  let complete: Bool

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack {
        Image(systemName: symbol)
          .font(.title2)
        Spacer()
        Image(systemName: complete ? "checkmark.circle.fill" : "lock.circle.fill")
          .foregroundStyle(complete ? .green : .orange)
      }
      Text(title)
        .font(.headline)
      Text(value)
        .font(.title3.weight(.semibold))
        .foregroundStyle(.secondary)
    }
    .padding(18)
    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    .overlay {
      RoundedRectangle(cornerRadius: 20, style: .continuous)
        .stroke(.white.opacity(0.1), lineWidth: 1)
    }
  }
}
