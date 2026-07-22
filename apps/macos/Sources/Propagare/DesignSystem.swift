import SwiftUI

enum PropagareDesign {
  static let black = Color(red: 0, green: 0, blue: 0)
  static let white = Color(red: 1, green: 1, blue: 1)
  static let muted = white.opacity(0.58)
  static let subtle = white.opacity(0.08)
  static let line = white.opacity(0.14)
  static let contentCornerRadius: CGFloat = 24
  static let compactCornerRadius: CGFloat = 16
  static let contentPadding: CGFloat = 18
  static let backdrop = black
}

private struct FunctionalGlassModifier: ViewModifier {
  let cornerRadius: CGFloat

  @ViewBuilder
  func body(content: Content) -> some View {
    if #available(macOS 26.0, *) {
      content
        .glassEffect(
          .regular.tint(PropagareDesign.white.opacity(0.035)),
          in: .rect(cornerRadius: cornerRadius)
        )
    } else {
      content
        .background(
          PropagareDesign.black.opacity(0.74),
          in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        )
        .overlay {
          RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .stroke(PropagareDesign.line, lineWidth: 1)
        }
    }
  }
}

private struct ProminentGlassButtonModifier: ViewModifier {
  @ViewBuilder
  func body(content: Content) -> some View {
    if #available(macOS 26.0, *) {
      content
        .buttonStyle(.glassProminent)
        .tint(PropagareDesign.white)
        .foregroundStyle(PropagareDesign.black)
    } else {
      content
        .buttonStyle(.borderedProminent)
        .tint(PropagareDesign.white)
        .foregroundStyle(PropagareDesign.black)
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
  var isInverted = false

  var body: some View {
    ZStack {
      Circle()
        .fill(
          isInverted ? PropagareDesign.black.opacity(0.08) : PropagareDesign.subtle
        )
      Circle()
        .strokeBorder(
          isInverted ? PropagareDesign.black.opacity(0.18) : PropagareDesign.line,
          lineWidth: 1
        )
      Text(initials)
        .font(.system(size: size * 0.3, weight: .semibold, design: .rounded))
        .foregroundStyle(isInverted ? PropagareDesign.black : PropagareDesign.white)
    }
    .frame(width: size, height: size)
    .accessibilityLabel(Text("Avatar \(initials)"))
  }
}
