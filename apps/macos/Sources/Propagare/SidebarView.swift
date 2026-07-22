import SwiftUI

struct SidebarView: View {
  let model: AppModel

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack(spacing: 10) {
        Text("P")
          .font(.system(size: 16, weight: .bold, design: .rounded))
          .foregroundStyle(PropagareDesign.black)
          .frame(width: 30, height: 30)
          .background(PropagareDesign.white, in: RoundedRectangle(cornerRadius: 9))
        Text("Propagare")
          .font(.headline)
          .foregroundStyle(PropagareDesign.white)
      }
      .padding(.horizontal, 16)
      .padding(.top, 14)
      .padding(.bottom, 22)

      VStack(spacing: 5) {
        ForEach(SidebarSelection.allCases) { item in
          Button {
            model.selection = item
          } label: {
            HStack(spacing: 11) {
              Image(systemName: item.symbol)
                .font(.system(size: 13, weight: .semibold))
                .frame(width: 20)
              Text(item.title)
                .font(.callout.weight(.medium))
              Spacer()
            }
            .foregroundStyle(
              model.selection == item ? PropagareDesign.black : PropagareDesign.white
            )
            .padding(.horizontal, 12)
            .frame(height: 38)
            .background {
              if model.selection == item {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                  .fill(PropagareDesign.white)
              }
            }
            .contentShape(Rectangle())
          }
          .buttonStyle(.plain)
          .accessibilityAddTraits(model.selection == item ? .isSelected : [])
        }
      }
      .padding(6)
      .functionalGlass(cornerRadius: 18)
      .padding(.horizontal, 10)

      Spacer()

      HStack(spacing: 9) {
        Circle()
          .fill(PropagareDesign.white)
          .frame(width: 6, height: 6)
        VStack(alignment: .leading, spacing: 2) {
          Text("SECURITY PREVIEW")
            .font(.caption2.weight(.semibold))
            .tracking(0.7)
          Text("Sending is locked")
            .font(.caption)
            .foregroundStyle(PropagareDesign.muted)
        }
      }
      .foregroundStyle(PropagareDesign.white)
      .padding(.horizontal, 16)
      .padding(.bottom, 16)
      .accessibilityElement(children: .combine)

      HStack(spacing: 10) {
        AvatarView(initials: "EN", color: .blue, size: 34)
        VStack(alignment: .leading, spacing: 1) {
          Text("Local Preview")
            .font(.callout.weight(.semibold))
          Text("No keys loaded")
            .font(.caption)
            .foregroundStyle(PropagareDesign.muted)
        }
        Spacer()
        Image(systemName: "gearshape")
          .foregroundStyle(PropagareDesign.muted)
      }
      .foregroundStyle(PropagareDesign.white)
      .padding(14)
      .overlay(alignment: .top) {
        Rectangle()
          .fill(PropagareDesign.line)
          .frame(height: 1)
      }
    }
    .background(PropagareDesign.black.opacity(0.88))
    .navigationTitle("")
  }
}
