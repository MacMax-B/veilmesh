import SwiftUI

enum PropagareDesign {
  static let contentCornerRadius: CGFloat = 22
  static let compactCornerRadius: CGFloat = 14
  static let contentPadding: CGFloat = 18

  static let backdrop = LinearGradient(
    colors: [
      Color(red: 0.035, green: 0.055, blue: 0.11),
      Color(red: 0.055, green: 0.13, blue: 0.19),
      Color(red: 0.13, green: 0.075, blue: 0.22),
    ],
    startPoint: .topLeading,
    endPoint: .bottomTrailing
  )
}

private struct FunctionalGlassModifier: ViewModifier {
  let cornerRadius: CGFloat

  @ViewBuilder
  func body(content: Content) -> some View {
    if #available(macOS 26.0, *) {
      content
        .glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
    } else {
      content
        .background(
          .ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        )
        .overlay {
          RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .stroke(.white.opacity(0.12), lineWidth: 1)
        }
    }
  }
}

private struct ProminentGlassButtonModifier: ViewModifier {
  @ViewBuilder
  func body(content: Content) -> some View {
    if #available(macOS 26.0, *) {
      content.buttonStyle(.glassProminent)
    } else {
      content.buttonStyle(.borderedProminent)
    }
  }
}

extension View {
  func functionalGlass(cornerRadius: CGFloat = PropagareDesign.compactCornerRadius) -> some View {
    modifier(FunctionalGlassModifier(cornerRadius: cornerRadius))
  }

  func prominentGlassButton() -> some View {
    modifier(ProminentGlassButtonModifier())
  }
}

struct AvatarView: View {
  let initials: String
  let color: AccentColor
  var size: CGFloat = 42

  var body: some View {
    ZStack {
      Circle()
        .fill(
          LinearGradient(
            colors: [color.color.opacity(0.95), color.color.opacity(0.48)],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
          )
        )
      Circle()
        .strokeBorder(.white.opacity(0.28), lineWidth: 1)
      Text(initials)
        .font(.system(size: size * 0.31, weight: .bold, design: .rounded))
        .foregroundStyle(.white)
    }
    .frame(width: size, height: size)
    .accessibilityLabel(Text("Avatar \(initials)"))
  }
}
