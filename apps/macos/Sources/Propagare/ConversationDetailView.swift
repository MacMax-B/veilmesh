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
    HStack(spacing: 10) {
      Image(systemName: "lock.fill")
        .font(.caption)
      VStack(alignment: .leading, spacing: 1) {
        Text("DIRECT · METADATA VISIBLE")
          .font(.caption2.weight(.semibold))
          .tracking(0.7)
        Text("One node protects content, not communication relationships.")
          .font(.caption2)
          .foregroundStyle(PropagareDesign.muted)
      }
      Spacer()
      Button {
        model.selection = .network
      } label: {
        Image(systemName: "chevron.right")
          .font(.caption.weight(.semibold))
      }
      .buttonStyle(.plain)
      .accessibilityLabel("Review Network Safety")
    }
    .foregroundStyle(PropagareDesign.white)
    .padding(.horizontal, 14)
    .frame(height: 46)
    .background(PropagareDesign.subtle, in: RoundedRectangle(cornerRadius: 15))
    .overlay {
      RoundedRectangle(cornerRadius: 15)
        .stroke(PropagareDesign.line, lineWidth: 1)
    }
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
        .foregroundStyle(PropagareDesign.white)
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
    .overlay {
      RoundedRectangle(cornerRadius: 22, style: .continuous)
        .stroke(PropagareDesign.line, lineWidth: 1)
    }
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
          .foregroundStyle(PropagareDesign.muted)
          .padding(.horizontal, 12)
          .padding(.vertical, 7)
          .background(PropagareDesign.subtle, in: Capsule())
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
          .foregroundStyle(
            message.direction == .outgoing
              ? PropagareDesign.black.opacity(0.58) : PropagareDesign.muted
          )
        }
        .foregroundStyle(
          message.direction == .outgoing ? PropagareDesign.black : PropagareDesign.white
        )
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
          message.direction == .outgoing ? PropagareDesign.white : PropagareDesign.subtle,
          in: RoundedRectangle(cornerRadius: 18, style: .continuous)
        )
        .overlay {
          if message.direction == .incoming {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
              .stroke(PropagareDesign.line, lineWidth: 1)
          }
        }
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
    ScrollView {
      VStack(spacing: 10) {
        AvatarView(initials: conversation.initials, color: conversation.color, size: 72)
        Text(conversation.title)
          .font(.title2.bold())
        Label(
          conversation.isVerified ? "Verified identity" : "Identity not verified",
          systemImage: conversation.isVerified
            ? "checkmark.seal.fill" : "exclamationmark.triangle.fill"
        )
        .foregroundStyle(PropagareDesign.white)
      }
      .frame(maxWidth: .infinity)
      .padding(.vertical, 24)

      VStack(alignment: .leading, spacing: 0) {
        Text("TRANSPORT")
          .font(.caption2.weight(.semibold))
          .tracking(0.7)
          .foregroundStyle(PropagareDesign.muted)
          .padding(.bottom, 10)

        InspectorMetric(title: "Connected nodes", value: "\(safety.connectedNodes)")
        InspectorMetric(
          title: "Independent operators",
          value: "\(safety.independentOperators)"
        )
        InspectorMetric(
          title: "Direct bootstrap",
          value: safety.canUseDirectBootstrap ? "Active" : "Inactive"
        )
        InspectorMetric(
          title: "Metadata anonymity",
          value: safety.canClaimMetadataAnonymity ? "Active" : "Locked",
          drawsDivider: false
        )
      }
      .padding(16)
      .background(PropagareDesign.subtle, in: RoundedRectangle(cornerRadius: 18))
      .overlay {
        RoundedRectangle(cornerRadius: 18)
          .stroke(PropagareDesign.line, lineWidth: 1)
      }
    }
    .padding(14)
    .foregroundStyle(PropagareDesign.white)
    .background(PropagareDesign.black)
  }
}

private struct InspectorMetric: View {
  let title: LocalizedStringKey
  let value: String
  var drawsDivider = true

  var body: some View {
    HStack {
      Text(title)
      Spacer()
      Text(value)
        .foregroundStyle(PropagareDesign.muted)
    }
    .font(.callout)
    .padding(.vertical, 11)
    .overlay(alignment: .bottom) {
      if drawsDivider {
        Rectangle()
          .fill(PropagareDesign.line)
          .frame(height: 1)
      }
    }
  }
}
