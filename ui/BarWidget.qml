import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

// One glyph: dim while the service is missing, lit while a site waits for
// your confirmation. The service owns the state.
BarWidget {
  id: root

  moduleName: "omapasskey"

  readonly property var passkeys: bar && bar.shell && typeof bar.shell.serviceFor === "function"
    ? bar.shell.serviceFor("omapasskey") : null
  readonly property bool drawsIcon: setting("showBarIcon", true) !== false
  readonly property bool ready: !!passkeys && passkeys.connected && passkeys.pinSet
  readonly property bool waiting: !!passkeys && passkeys.waiting

  // The shell hands settings to the bar widget, not to the service.
  function pushSettings() {
    if (passkeys && typeof passkeys.applySettings === "function") passkeys.applySettings(settings)
  }
  onSettingsChanged: pushSettings()
  onPasskeysChanged: pushSettings()
  Component.onCompleted: pushSettings()

  visible: drawsIcon
  implicitWidth: drawsIcon ? button.implicitWidth : 0
  implicitHeight: drawsIcon ? button.implicitHeight : 0

  BarIconButton {
    id: button
    anchors.centerIn: parent
    bar: root.bar
    // nf-md-shield_key
    text: "󰯄"
    dimmed: !root.ready && !root.waiting
    active: root.waiting || (!!root.passkeys && root.passkeys.winking)
    tooltipText: root.passkeys ? root.passkeys.tooltip : "Omapasskey"

    // Needs attention: not installed, not running, or no PIN yet.
    Rectangle {
      visible: !!root.passkeys && root.passkeys.installChecked && !root.ready && !root.waiting
      width: Style.space(5)
      height: width
      radius: width / 2
      color: Color.urgent
      border.color: Color.bar.background
      border.width: 1
      anchors.horizontalCenter: parent.horizontalCenter
      anchors.verticalCenter: parent.verticalCenter
      anchors.horizontalCenterOffset: Style.bar.iconCanvas * 0.42
      anchors.verticalCenterOffset: -Style.bar.iconCanvas * 0.42
    }

    onPressed: function(buttonCode) {
      if (!root.passkeys) return
      if (buttonCode === Qt.LeftButton) root.passkeys.primaryAction()
      else if (buttonCode === Qt.MiddleButton) root.passkeys.changePin()
      else if (buttonCode === Qt.RightButton) root.passkeys.openManager()
    }
  }
}
