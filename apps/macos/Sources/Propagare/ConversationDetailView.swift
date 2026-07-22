import PropagareSafety
import SwiftUI

struct ConversationDetailView: View {
  let model: AppModel
  let conversation: Conversation

  private var draft: Binding<String> {
    Binding(
      get: { model.draft },
      set: { model.draft = $0 }
    )
  }

  private var showsInspector: Binding<Bool> {
    Binding(
      get: { model.showsInspector },
      set: { model.showsInspector = $0 }
    )
  }

  var body: some View {
    ZStack {
      PropagareDesign.backdrop
        .ignoresSafeArea()

      VStack(spacing: 0) {
        ScrollView {
          LazyVStack(spacing: 12) {
            safetyBanner
            ForEach(conversation.messages) { message in
              MessageBubble(message: message)
            }
          }
          .padding(PropagareDesign.contentPadding)
          .frame(maxWidth: 860)
          .frame(maxWidth: .infinity)
        }

        composer
          .padding(PropagareDesign.contentPadding)
      }
    }
    .navigationTitle(conversation.title)
    .toolbar {
      ToolbarItemGroup {
        Button {
        } label: {
          Label("Start Audio Call", systemImage: "phone")
        }
        .disabled(true)
        .help("Calls require the production Core service")

        Button {
        } label: {
          Label("Start Video Call", systemImage: "video")
        }
        .disabled(true)
        .help("Calls require the production Core service")

        Button {
          model.showsInspector.toggle()
        } label: {
          Label("Conversation Info", systemImage: "info.circle")
        }
        .accessibilityLabel("Conversation Info")
      }
    }
    .inspector(isPresented: showsInspector) {
      ConversationInspector(conversation: conversation, safety: model.networkSafety)
        .inspectorColumnWidth(min: 250, ideal: 290, max: 350)
    }
    .alert(
      "Message Not Sent",
      isPresented: Binding(
        get: { model.composerError != nil },
        set: { if !$0 { model.composerError = nil } }
      )
    ) {
      Button("OK", role: .cancel) {}
    } message: {
      Text(model.composerError ?? "")
    }
  }

  private var safetyBanner: some View {
    HStack(spacing: 12) {
      Image(systemName: "shield.lefthalf.filled.trianglebadge.exclamationmark")
        .font(.title3)
        .foregroundStyle(.orange)
      VStack(alignment: .leading, spacing: 2) {
        Text("Metadata protection is not active")
          .font(.callout.weight(.semibold))
        Text("A single direct node cannot hide who communicates with whom.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
      Button("Review") {
        model.selection = .network
      }
    }
    .padding(14)
    .functionalGlass(cornerRadius: 18)
    .accessibilityElement(children: .combine)
  }

  private var composer: some View {
    HStack(alignment: .bottom, spacing: 10) {
      Button {
      } label: {
        Image(systemName: "plus")
          .frame(width: 28, height: 28)
      }
      .disabled(true)
      .help("Attachments require the production Core service")
      .accessibilityLabel("Add Attachment")

      TextField("Write a message", text: draft, axis: .vertical)
        .textFieldStyle(.plain)
        .lineLimit(1...6)
        .padding(.horizontal, 6)
        .onSubmit {
          Task { await model.sendDraft() }
        }

      Button {
        Task { await model.sendDraft() }
      } label: {
        Image(systemName: "arrow.up")
          .font(.body.bold())
          .frame(width: 28, height: 28)
      }
      .prominentGlassButton()
      .disabled(!model.canSend)
      .help("Sending remains safety-locked")
      .accessibilityLabel("Send Message")
    }
    .padding(12)
    .functionalGlass(cornerRadius: 22)
    .frame(maxWidth: 860)
  }
}

private struct MessageBubble: View {
  let message: ChatMessage

  var body: some View {
    HStack {
      if message.direction == .outgoing { Spacer(minLength: 110) }
      if message.direction == .system {
        Text(message.body)
          .font(.caption)
          .foregroundStyle(.secondary)
          .padding(.horizontal, 12)
          .padding(.vertical, 7)
          .background(.black.opacity(0.18), in: Capsule())
      } else {
        VStack(alignment: .leading, spacing: 7) {
          Text(message.body)
            .textSelection(.enabled)
          HStack(spacing: 5) {
            Text(message.timestamp, style: .time)
            if message.direction == .outgoing {
              Image(systemName: message.delivery == .delivered ? "checkmark.circle.fill" : "clock")
            }
          }
          .font(.caption2)
          .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
          message.direction == .outgoing ? Color.blue.opacity(0.75) : Color.white.opacity(0.12),
          in: RoundedRectangle(cornerRadius: 18, style: .continuous)
        )
      }
      if message.direction == .incoming { Spacer(minLength: 110) }
    }
    .frame(maxWidth: .infinity)
  }
}

private struct ConversationInspector: View {
  let conversation: Conversation
  let safety: NetworkSafety

  var body: some View {
    Form {
      VStack(spacing: 10) {
        AvatarView(initials: conversation.initials, color: conversation.color, size: 72)
        Text(conversation.title)
          .font(.title2.bold())
        Label(
          conversation.isVerified ? "Verified identity" : "Identity not verified",
          systemImage: conversation.isVerified
            ? "checkmark.seal.fill" : "exclamationmark.triangle.fill"
        )
        .foregroundStyle(conversation.isVerified ? .cyan : .orange)
      }
      .frame(maxWidth: .infinity)
      .padding(.vertical)

      Section("Transport") {
        LabeledContent("Connected nodes", value: "\(safety.connectedNodes)")
        LabeledContent("Independent operators", value: "\(safety.independentOperators)")
        LabeledContent(
          "Direct bootstrap", value: safety.canUseDirectBootstrap ? "Active" : "Inactive")
        LabeledContent(
          "Metadata anonymity", value: safety.canClaimMetadataAnonymity ? "Active" : "Locked")
      }
    }
    .formStyle(.grouped)
  }
}
