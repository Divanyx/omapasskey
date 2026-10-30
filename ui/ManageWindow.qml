import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import Quickshell.Hyprland
import Quickshell.Wayland
import qs.Commons
import qs.Commons as Commons

// The passkey manager (right click on the bar icon). Listing and deleting
// both go to the service with the PIN and wait for the key combination on a
// physical keyboard; the PIN stays in this window's memory only while it is
// open, and is forgotten on close or after five minutes.
PanelWindow {
  id: win

  property var service: null
  property string pin: ""
  property var accounts: []
  // "locked", "waiting", "list", "error"
  property string phase: "locked"
  property string message: ""
  property string confirmDelete: ""
  // The request a retry would repeat (without the PIN once it is forgotten).
  property var lastRequest: null
  // Each request gets a number; an answer for an older one is dropped.
  property int seq: 0
  property int answering: 0
  // The screen is chosen when the panel opens and kept while it is open, so
  // focusing another monitor does not re-create it and drop the focus.
  property var pinnedScreen: null

  readonly property string managePath: "/run/omapasskey/manage.sock"
  readonly property color fg: Commons.Color.foreground
  readonly property color bg: Commons.Color.background
  readonly property color acc: Commons.Color.accent
  readonly property string keysText: service && service.confirmKeys.length ? service.confirmKeys.join(" + ") : "Left Shift + Right Shift"

  visible: false
  color: "transparent"
  screen: pinnedScreen
  anchors { top: true; bottom: true; left: true; right: true }
  exclusionMode: ExclusionMode.Ignore
  WlrLayershell.namespace: "omapasskey-manager"
  WlrLayershell.layer: WlrLayer.Overlay
  // The keyboard is taken only while the PIN is typed. Otherwise the panel
  // takes it on demand (clicks), so the rest of the desktop stays usable.
  WlrLayershell.keyboardFocus: !visible ? WlrKeyboardFocus.None
    : phase === "locked" ? WlrKeyboardFocus.Exclusive : WlrKeyboardFocus.OnDemand

  function focusedScreen() {
    var name = Hyprland.focusedMonitor ? String(Hyprland.focusedMonitor.name || "") : ""
    var screens = Quickshell.screens
    for (var i = 0; i < screens.length; i++)
      if (screens[i].name === name) return screens[i]
    return screens.length > 0 ? screens[0] : null
  }

  function open() {
    if (visible) return
    forget()
    pinnedScreen = focusedScreen()
    visible = true
    Qt.callLater(function() { pinField.forceActiveFocus() })
  }

  function close() { visible = false }

  // Drops everything the panel learned: the PIN, the list, any request still
  // waiting for the key press (closing the connection cancels it in the
  // service, so a late key press changes nothing).
  function forget() {
    conn.connected = false
    pending = null
    lastRequest = null
    answering = 0
    pin = ""
    accounts = []
    phase = "locked"
    message = ""
    confirmDelete = ""
    pinField.text = ""
  }

  onVisibleChanged: if (!visible) forget()

  // Idle limit: five minutes without using the panel forgets the PIN.
  Timer {
    id: idle
    interval: 5 * 60 * 1000
    running: win.visible && win.pin !== ""
    onTriggered: { win.forget(); win.message = "Locked again after five idle minutes." }
  }

  // ------------------------------------------------------------ requests
  property var pending: null

  function request(payload) {
    if (phase === "waiting") return
    idle.restart()
    seq += 1
    answering = seq
    lastRequest = { cmd: payload.cmd, id: payload.id }
    pending = payload
    phase = "waiting"
    message = ""
    conn.connected = false
    conn.connected = true
  }

  function retry() {
    if (!lastRequest || pin === "") { phase = "locked"; return }
    request({ cmd: lastRequest.cmd, id: lastRequest.id, pin: pin })
  }

  function unlock() {
    if (pinField.text.length === 0) return
    pin = pinField.text
    pinField.text = ""
    request({ cmd: "list", pin: pin })
  }

  function remove(id) {
    confirmDelete = ""
    request({ cmd: "delete", pin: pin, id: id })
  }

  function handle(line) {
    if (!visible || answering !== seq || phase !== "waiting") return
    answering = 0
    var r = null
    try { r = JSON.parse(line) } catch (e) { r = null }
    conn.connected = false
    if (!r) { phase = "error"; message = "The service sent no answer."; return }
    if (!r.ok) {
      message = String(r.error || "failed")
      // A wrong PIN is forgotten together with whatever it unlocked.
      if (/PIN|blocked|lockout/i.test(message)) {
        pin = ""
        accounts = []
        phase = "locked"
        Qt.callLater(function() { pinField.forceActiveFocus() })
        return
      }
      phase = "error"
      return
    }
    accounts = r.data || []
    phase = "list"
  }

  Socket {
    id: conn
    path: win.managePath
    connected: false
    parser: SplitParser {
      onRead: function(data) { win.handle(data) }
    }
    onConnectionStateChanged: {
      if (conn.connected && win.pending) {
        conn.write(JSON.stringify(win.pending) + "\n")
        conn.flush()
        win.pending = null
      }
    }
    onError: {
      if (win.phase === "waiting") {
        win.pending = null
        win.phase = "error"
        win.message = "The Omapasskey service is not reachable."
      }
    }
  }

  Shortcut {
    sequence: "Escape"
    enabled: win.visible
    onActivated: win.close()
  }

  // Website-chosen text: no line breaks, no direction overrides (which could
  // forge another line or reverse a name), bounded length.
  function clean(text, max) {
    var t = String(text || "").replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, " ")
    t = t.replace(/\s+/g, " ").trim()
    return t.length > max ? t.substring(0, max - 1) + "…" : t
  }

  // Base64 of the ID (from JSON) to a short hex prefix for display.
  function shortId(b64) {
    var raw = Qt.atob(String(b64 || ""))
    var hex = ""
    for (var i = 0; i < Math.min(6, raw.length); i++) {
      var h = raw.charCodeAt(i).toString(16)
      hex += h.length < 2 ? "0" + h : h
    }
    return hex
  }

  function created(sec) {
    var d = new Date(Number(sec) * 1000)
    function two(n) { return n < 10 ? "0" + n : String(n) }
    return two(d.getDate()) + "-" + two(d.getMonth() + 1) + "-" + d.getFullYear() + " " + two(d.getHours()) + ":" + two(d.getMinutes())
  }

  function details(a) {
    var lines = []
    if (a.displayName) lines.push("Name: " + clean(a.displayName, 80))
    if (a.userName) lines.push("Account: " + clean(a.userName, 80))
    lines.push("Site: " + clean(a.rpId, 80) + (a.rpName && a.rpName !== a.rpId ? " (" + clean(a.rpName, 60) + ")" : ""))
    lines.push("Created: " + created(a.created))
    lines.push("Kind: " + (a.discoverable ? "passkey (sign in without a username)" : "security key (second factor)"))
    lines.push("PRF / encryption keys: " + (a.prf ? "yes" : "no"))
    lines.push("Protection: " + (a.credProtect === 3 ? "always needs the PIN" : a.credProtect === 2 ? "PIN unless the site names it" : "standard"))
    lines.push("ID: " + shortId(a.id) + "…")
    return lines.join("\n")
  }

  // ------------------------------------------------------------ layout
  Rectangle {
    anchors.fill: parent
    color: Qt.rgba(0, 0, 0, 0.45)
    MouseArea {
      anchors.fill: parent
      onClicked: win.close()
    }
  }

  Rectangle {
    id: card
    width: Math.min(620, win.width - 40)
    height: Math.min(640, win.height - 80)
    anchors.centerIn: parent
    color: win.bg
    radius: Math.max(4, Style.cornerRadius)
    border.color: win.acc
    border.width: 2
    // Swallow clicks so they do not close the panel.
    MouseArea { anchors.fill: parent }

  Column {
    anchors.fill: parent
    anchors.margins: 22
    spacing: 16

    Row {
      spacing: 12
      Text {
        textFormat: Text.PlainText
        text: "󰯄"
        color: win.acc
        font.family: Style.font.family
        font.pixelSize: 30
      }
      Column {
        anchors.verticalCenter: parent.verticalCenter
        Text {
          textFormat: Text.PlainText
          text: "Passkeys on this computer"
          color: win.fg
          font.family: Style.font.family
          font.pixelSize: 18
          font.bold: true
        }
        Text {
          textFormat: Text.PlainText
          text: win.phase === "list" ? win.accounts.length + " stored in the TPM · hover for details" : "Kept in the TPM, unlocked with your PIN"
          color: Util.alpha(win.fg, 0.6)
          font.family: Style.font.family
          font.pixelSize: 13
        }
      }
    }

    // PIN entry
    Column {
      visible: win.phase === "locked"
      width: parent.width
      spacing: 10
      Text {
        textFormat: Text.PlainText
        width: parent.width
        wrapMode: Text.WordWrap
        text: "Enter your passkey PIN. Omapasskey then asks you to press " + win.keysText + " on your keyboard."
        color: win.fg
        font.family: Style.font.family
        font.pixelSize: 14
      }
      Rectangle {
        width: parent.width
        height: 42
        radius: 6
        color: Util.alpha(win.fg, 0.06)
        border.color: pinField.activeFocus ? win.acc : Util.alpha(win.fg, 0.25)
        TextInput {
          id: pinField
          anchors.fill: parent
          anchors.leftMargin: 12
          anchors.rightMargin: 12
          verticalAlignment: TextInput.AlignVCenter
          echoMode: TextInput.Password
          inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
          color: win.fg
          font.family: Style.font.family
          font.pixelSize: 16
          focus: true
          onAccepted: win.unlock()
          Keys.onEscapePressed: win.close()
        }
      }
      Text {
        textFormat: Text.PlainText
        visible: win.message !== ""
        width: parent.width
        wrapMode: Text.WordWrap
        text: win.message
        color: Commons.Color.urgent
        font.family: Style.font.family
        font.pixelSize: 13
      }
    }

    // Waiting for the key press
    Column {
      visible: win.phase === "waiting"
      width: parent.width
      spacing: 8
      Text {
        textFormat: Text.PlainText
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
        text: "Press " + win.keysText
        color: win.acc
        font.family: Style.font.family
        font.pixelSize: 20
        font.bold: true
      }
      Text {
        textFormat: Text.PlainText
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
        text: "on your physical keyboard to show or change your passkeys"
        color: Util.alpha(win.fg, 0.7)
        font.family: Style.font.family
        font.pixelSize: 13
      }
    }

    Text {
      textFormat: Text.PlainText
      visible: win.phase === "error"
      width: parent.width
      wrapMode: Text.WordWrap
      text: win.message
      color: Commons.Color.urgent
      font.family: Style.font.family
      font.pixelSize: 14
    }

    Rectangle {
      visible: win.phase === "error"
      width: retryLabel.implicitWidth + 28
      height: 34
      radius: 6
      color: retryArea.containsMouse ? Util.alpha(win.acc, 0.3) : Util.alpha(win.acc, 0.15)
      border.color: win.acc
      Text {
        id: retryLabel
        textFormat: Text.PlainText
        anchors.centerIn: parent
        text: win.pin === "" ? "Enter the PIN again" : "Try again"
        color: win.fg
        font.family: Style.font.family
        font.pixelSize: 13
      }
      MouseArea {
        id: retryArea
        anchors.fill: parent
        hoverEnabled: true
        onClicked: win.retry()
      }
    }

    // The list
    ListView {
      id: list
      visible: win.phase === "list"
      width: parent.width
      height: card.height - 150
      clip: true
      spacing: 6
      model: win.accounts

      Text {
        textFormat: Text.PlainText
        visible: list.count === 0
        anchors.centerIn: parent
        text: "No passkeys yet. Register one on a site, e.g. webauthn.io."
        color: Util.alpha(win.fg, 0.6)
        font.family: Style.font.family
        font.pixelSize: 14
      }

      delegate: Rectangle {
        required property var modelData
        width: list.width
        height: 58
        radius: 6
        color: hover.hovered ? Util.alpha(win.fg, 0.10) : Util.alpha(win.fg, 0.05)

        HoverHandler { id: hover }
        // Site and account names come from the registering website, so the
        // tooltip, like every text here, is plain text: no markup, no image
        // tags that would make the shell fetch a URL.
        ToolTip {
          visible: hover.hovered && win.confirmDelete === ""
          delay: 350
          contentItem: Text {
            textFormat: Text.PlainText
            wrapMode: Text.WrapAnywhere
            width: Math.min(implicitWidth, 460)
            text: win.details(modelData)
            color: win.fg
            font.family: Style.font.family
            font.pixelSize: 12
          }
          background: Rectangle {
            color: Qt.lighter(win.bg, 1.3)
            border.color: Util.alpha(win.fg, 0.3)
            radius: 4
          }
        }

        Column {
          anchors.left: parent.left
          anchors.leftMargin: 14
          anchors.right: actions.left
          anchors.rightMargin: 10
          anchors.verticalCenter: parent.verticalCenter
          spacing: 3
          Text {
            textFormat: Text.PlainText
            width: parent.width
            elide: Text.ElideRight
            text: win.clean(modelData.rpId, 80)
            color: win.fg
            font.family: Style.font.family
            font.pixelSize: 15
            font.bold: true
          }
          Text {
            textFormat: Text.PlainText
            width: parent.width
            elide: Text.ElideRight
            text: win.clean(modelData.userName || modelData.displayName || "—", 60) + "  ·  " + (modelData.discoverable ? "passkey" : "security key") + (modelData.prf ? " · PRF" : "")
            color: Util.alpha(win.fg, 0.65)
            font.family: Style.font.family
            font.pixelSize: 12
          }
        }

        Row {
          id: actions
          anchors.right: parent.right
          anchors.rightMargin: 12
          anchors.verticalCenter: parent.verticalCenter
          spacing: 8

          Text {
            textFormat: Text.PlainText
            visible: win.confirmDelete === modelData.id
            anchors.verticalCenter: parent.verticalCenter
            text: "Delete?"
            color: Commons.Color.urgent
            font.family: Style.font.family
            font.pixelSize: 13
          }
          Rectangle {
            width: 34
            height: 30
            radius: 5
            color: win.confirmDelete === modelData.id ? Commons.Color.urgent : (trashArea.containsMouse ? Util.alpha(Commons.Color.urgent, 0.25) : "transparent")
            Text {
              textFormat: Text.PlainText
              anchors.centerIn: parent
              // nf-md-trash_can_outline / check
              text: win.confirmDelete === modelData.id ? "󰄬" : "󰩺"
              color: win.confirmDelete === modelData.id ? win.bg : Commons.Color.urgent
              font.family: Style.font.family
              font.pixelSize: 17
            }
            MouseArea {
              id: trashArea
              anchors.fill: parent
              hoverEnabled: true
              enabled: win.phase === "list"
              onClicked: win.confirmDelete === modelData.id ? win.remove(modelData.id) : (win.confirmDelete = modelData.id)
            }
          }
          Rectangle {
            visible: win.confirmDelete === modelData.id
            width: 34
            height: 30
            radius: 5
            color: Util.alpha(win.fg, 0.1)
            Text {
              textFormat: Text.PlainText
              anchors.centerIn: parent
              text: "󰅖"
              color: win.fg
              font.family: Style.font.family
              font.pixelSize: 17
            }
            MouseArea {
              anchors.fill: parent
              onClicked: win.confirmDelete = ""
            }
          }
        }
      }
    }

    Text {
      textFormat: Text.PlainText
      visible: win.phase === "list"
      width: parent.width
      wrapMode: Text.WordWrap
      text: "Deleting here removes the key from this computer only — remove it in the site's security settings too."
      color: Util.alpha(win.fg, 0.5)
      font.family: Style.font.family
      font.pixelSize: 11
    }
  }
}
}
