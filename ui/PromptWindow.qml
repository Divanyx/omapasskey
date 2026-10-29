import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Wayland
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// The confirmation card. It never takes keyboard focus and lets every click
// through: the browser keeps focus, and the Shift keys are read by the
// service straight from the keyboard, not from this window.
PanelWindow {
  id: win

  property var service: null

  readonly property var shown: service ? (service.prompt || service.outcomePrompt) : null
  readonly property bool noteOnly: service !== null && shown === null && service.note !== null
  readonly property bool reset: shown !== null && shown.op === "reset"
  readonly property color accent: reset ? Commons.Color.urgent : Commons.Color.accent
  readonly property color text: Commons.Color.popups.text
  readonly property int pad: Style.space(22)

  // The confirming keys, as the service announced them.
  readonly property var keyLabels: {
    var p = service ? (service.prompt || service.outcomePrompt) : null
    var k = p && p.keys && p.keys.length ? p.keys : (service && service.confirmKeys.length ? service.confirmKeys : ["Left Shift", "Right Shift"])
    return k
  }
  readonly property var keycaps: {
    var out = []
    for (var i = 0; i < keyLabels.length; i++) {
      if (i > 0) out.push("+")
      out.push(String(keyLabels[i]).replace(/^Left Shift$/, "⇧  Shift").replace(/^Right Shift$/, "Shift  ⇧"))
    }
    return out
  }
  readonly property string keysText: keyLabels.join(" + ")

  // Glyphs from the Nerd Font the shell already uses.
  readonly property string glyphShieldKey: "󰯄"
  readonly property string glyphCheck: "󰗠"
  readonly property string glyphClose: "󰅙"
  readonly property string glyphAlert: "󰻌"

  visible: shown !== null || noteOnly
  screen: {
    var name = Hyprland.focusedMonitor ? String(Hyprland.focusedMonitor.name || "") : ""
    var screens = Quickshell.screens
    for (var i = 0; i < screens.length; i++)
      if (screens[i].name === name) return screens[i]
    return screens.length > 0 ? screens[0] : null
  }
  anchors { top: true; bottom: true; left: true; right: true }
  color: "transparent"
  exclusionMode: ExclusionMode.Ignore
  WlrLayershell.namespace: "omapasskey-prompt"
  WlrLayershell.layer: WlrLayer.Overlay
  WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
  mask: Region {}

  function outcomeText(outcome) {
    switch (outcome) {
    case "confirmed": return "Confirmed"
    case "timeout": return "Timed out — nothing was signed"
    case "denied": return "Cancelled"
    case "cancelled": return "Cancelled by the browser"
    case "no-keyboard": return "No physical keyboard found"
    }
    return "Not confirmed"
  }

  // While a site waits, the rest of the screen steps back, so the question
  // cannot be missed. Clicks still pass through.
  Rectangle {
    anchors.fill: parent
    color: Qt.rgba(0, 0, 0, 1)
    opacity: win.service && win.service.waiting ? 0.35 : 0
    Behavior on opacity { NumberAnimation { duration: 180 } }
  }

  BorderSurface {
    id: card
    width: Math.min(win.width - Style.space(40), Style.space(520))
    height: content.implicitHeight + card.borderTop + card.borderBottom + 2 * win.pad
    anchors.horizontalCenter: parent.horizontalCenter
    y: win.service && win.service.promptPosition === "Top" ? Style.space(60)
      : win.service && win.service.promptPosition === "Bottom" ? parent.height - height - Style.space(80)
      : Math.round((parent.height - height) / 2)
    color: Commons.Color.background
    borderSpec: Border.surfaceSpec("popups", "border", win.accent, Math.max(2, Style.space(2)))
    radius: Style.cornerRadius
    opacity: win.visible ? 1 : 0
    scale: win.visible ? 1 : 0.97
    Behavior on opacity { NumberAnimation { duration: 120 } }
    Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }

    Column {
      id: content
      x: card.borderLeft + win.pad
      y: card.borderTop + win.pad
      width: card.width - card.borderLeft - card.borderRight - 2 * win.pad
      spacing: Style.space(14)

      // Headline: what is being asked, and by whom.
      Row {
        width: parent.width
        spacing: Style.space(14)

        Text {
          id: icon
          textFormat: Text.PlainText
          text: win.noteOnly ? win.glyphCheck
            : win.service && win.service.outcome === "confirmed" ? win.glyphCheck
            : win.service && win.service.outcome !== "" ? win.glyphClose
            : win.reset ? win.glyphAlert : win.glyphShieldKey
          color: win.accent
          font.family: Style.font.family
          font.pixelSize: Style.font.displayLarge
          anchors.verticalCenter: parent.verticalCenter
        }

        Column {
          width: parent.width - icon.width - parent.spacing
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(3)

          Text {
            width: parent.width
            textFormat: Text.PlainText
            elide: Text.ElideMiddle
            text: win.noteOnly
              ? (win.service.note.op === "register" ? "Passkey created for " : "Signed in to ") + (win.service.note.rp || "a site")
              : win.service ? win.service.describe(win.shown) : ""
            color: win.text
            font.family: Style.font.family
            font.pixelSize: Style.font.title
            font.bold: true
          }

          Text {
            width: parent.width
            textFormat: Text.PlainText
            elide: Text.ElideRight
            text: win.noteOnly ? "with a passkey from this computer's TPM"
              : win.service && win.service.outcome !== "" ? win.outcomeText(win.service.outcome)
              : win.reset ? "Every passkey on this computer will be erased"
              : "Omapasskey · TPM passkey"
            color: Util.alpha(win.text, 0.7)
            font.family: Style.font.family
            font.pixelSize: Style.font.body
          }
        }
      }

      // The gesture: both Shift keys together.
      Row {
        visible: !win.noteOnly && win.service !== null && win.service.waiting
        anchors.horizontalCenter: parent.horizontalCenter
        spacing: Style.space(12)

        Repeater {
          model: win.keycaps

          Item {
            width: modelData === "+" ? plus.implicitWidth : Math.max(keyLabel.implicitWidth + Style.space(28), Style.space(110))
            height: Style.space(40)

            Rectangle {
              visible: modelData !== "+"
              anchors.fill: parent
              radius: Math.max(3, Style.cornerRadius)
              color: Util.alpha(win.accent, 0.12)
              border.width: Math.max(1, Style.space(1.5))
              border.color: win.accent

              // A slow pulse invites the press.
              SequentialAnimation on opacity {
                running: win.visible && win.service && win.service.waiting
                loops: Animation.Infinite
                NumberAnimation { from: 1; to: 0.55; duration: 900; easing.type: Easing.InOutSine }
                NumberAnimation { from: 0.55; to: 1; duration: 900; easing.type: Easing.InOutSine }
              }
            }

            Text {
              id: keyLabel
              visible: modelData !== "+"
              anchors.centerIn: parent
              textFormat: Text.PlainText
              text: modelData
              color: win.text
              font.family: Style.font.family
              font.pixelSize: Style.font.body
              font.bold: true
            }

            Text {
              id: plus
              visible: modelData === "+"
              anchors.centerIn: parent
              textFormat: Text.PlainText
              text: "+"
              color: Util.alpha(win.text, 0.7)
              font.family: Style.font.family
              font.pixelSize: Style.font.title
            }
          }
        }
      }

      Text {
        visible: !win.noteOnly && win.service !== null && win.service.waiting
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
        text: win.reset
          ? "Press " + win.keysText + " only if you really want to erase everything."
          : "Press " + win.keysText + " together to confirm"
        color: win.text
        font.family: Style.font.family
        font.pixelSize: Style.font.body
      }

      // Time left before the request lapses.
      Rectangle {
        id: track
        visible: !win.noteOnly && win.service !== null && win.service.waiting
        width: parent.width
        height: Math.max(Style.space(4), 3)
        radius: height / 2
        color: Util.alpha(win.text, 0.18)

        Rectangle {
          id: bar
          height: parent.height
          radius: parent.radius
          color: win.accent
          width: parent.width

          NumberAnimation on width {
            id: countdown
            running: false
            from: track.width
            to: 0
          }
        }

        Connections {
          target: win.service
          function onPromptStartedChanged() {
            if (!win.service || !win.service.prompt) return
            countdown.stop()
            countdown.duration = Math.max(1000, Number(win.service.prompt.timeoutMs) || 30000)
            countdown.start()
          }
        }
      }

      Text {
        visible: !win.noteOnly && win.service !== null && win.service.waiting
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
        text: "Esc cancels · only a physical keyboard counts, no program can press these"
        color: Util.alpha(win.text, 0.55)
        font.family: Style.font.family
        font.pixelSize: Math.max(10, Style.font.body - 2)
      }
    }
  }
}
