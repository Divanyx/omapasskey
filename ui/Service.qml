import QtQuick
import Quickshell
import Quickshell.Io

// Follows the Omapasskey system service over its read-only status socket and
// shows its confirmation prompts. Nothing here can approve anything: the
// service only accepts a key press on a physical keyboard, which it reads
// itself. This plugin just tells you which site is asking.
Item {
  id: root

  visible: false
  width: 0
  height: 0

  // Injected by the shell.
  property var shell: null
  property var manifest: null
  property var pluginRegistry: null
  property var barWidgetRegistry: null

  property string socketPath: "/run/omapasskey/status.sock"
  readonly property string daemonPath: "/usr/local/lib/omapasskey/omapasskeyd"
  // setup/ sits next to ui/ in the folder `omarchy plugin add` cloned.
  readonly property string pluginDir: decodeURIComponent(String(Qt.resolvedUrl("..")).replace(/^file:\/\//, "")).replace(/\/$/, "")
  readonly property string setupScript: pluginDir + "/setup/omapasskey-setup"

  property var settings: ({})
  property bool installed: false
  property bool installChecked: false
  property bool connected: false
  property string version: ""
  property bool pinSet: false
  property int pinRetries: 8
  property int keyboards: 0
  property string device: ""

  // The confirmation the service is waiting for, or null.
  property var prompt: null
  property double promptStarted: 0
  // How the last prompt ended, shown briefly: "confirmed", "timeout", ...
  property string outcome: ""
  property var outcomePrompt: null
  // The last completed use, for the optional note.
  property var note: null
  property bool winking: false

  readonly property bool waiting: prompt !== null
  readonly property string pluginVersion: manifest && manifest.version ? String(manifest.version) : ""
  // `omarchy plugin update` brings a newer setup script; the service follows
  // only when you run it, because that takes sudo.
  readonly property bool updateAvailable: connected && version !== "" && version !== "dev"
    && pluginVersion !== "" && version !== pluginVersion
  readonly property string promptPosition: settings.promptPosition === "Top" || settings.promptPosition === "Bottom"
    ? settings.promptPosition : "Center"

  readonly property string tooltip: !installChecked ? "Omapasskey"
    : !installed ? "Omapasskey — not set up yet: click to install the TPM passkey service"
    : !connected ? "Omapasskey — the service is not running: click for details"
    : waiting ? "Omapasskey — " + describe(prompt) + ": press Left Shift + Right Shift"
    : !pinSet ? "Omapasskey — no PIN yet: click to set one"
    : updateAvailable ? "Omapasskey — service " + version + ", plugin " + pluginVersion + ": click to update"
    : pinRetries < 8 ? "Omapasskey — ready (" + pinRetries + " of 8 PIN tries left)"
    : "Omapasskey — passkeys ready on /dev/" + (device || "?")

  function applySettings(values) {
    settings = values || ({})
  }

  // What a prompt asks for, in words.
  function describe(p) {
    if (!p) return ""
    var rp = String(p.rp || "")
    switch (String(p.op || "")) {
    case "sign-in": return rp ? "Sign in to " + rp : "Sign in with a passkey"
    case "register": return rp ? "Create a passkey for " + rp : "Create a passkey"
    case "unlock": return rp ? "Use a passkey for " + rp : "Unlock your passkeys"
    case "manage": return "Manage your passkeys"
    case "set-pin": return "Set the passkey PIN"
    case "change-pin": return "Change the passkey PIN"
    case "reset": return "Delete ALL passkeys"
    case "select": return "Use this computer's passkeys"
    case "exclude": return rp ? "Already registered at " + rp : "Already registered"
    }
    return "Confirm"
  }

  function handleLine(line) {
    var m = null
    try { m = JSON.parse(line) } catch (e) { return }
    if (!m || typeof m !== "object") return
    switch (m.type) {
    case "hello":
    case "state":
      applyState(m.state || {})
      if (m.type === "hello") {
        if (m.state && m.state.prompt) startPrompt(m.state.prompt)
        else prompt = null
      }
      break
    case "prompt":
      startPrompt(m.prompt)
      break
    case "prompt-end":
      if (prompt && Number(m.id) === Number(prompt.id)) {
        outcomePrompt = prompt
        outcome = String(m.result || "")
        prompt = null
        outcomeTimer.restart()
      }
      break
    case "done":
      if (m.ok && settings.usageNotes === true && (m.op === "sign-in" || m.op === "register")) {
        note = { op: m.op, rp: String(m.rp || "") }
        noteTimer.restart()
      }
      break
    case "wink":
      winking = true
      winkTimer.restart()
      break
    }
  }

  function applyState(s) {
    if (s.version !== undefined) version = String(s.version)
    if (s.pinSet !== undefined) pinSet = s.pinSet === true
    if (s.pinRetries !== undefined) pinRetries = Number(s.pinRetries) || 0
    if (s.keyboards !== undefined) keyboards = Number(s.keyboards) || 0
    if (s.device !== undefined) device = String(s.device || "")
  }

  function startPrompt(p) {
    if (!p) return
    outcome = ""
    outcomeTimer.stop()
    promptStarted = Date.now()
    prompt = p
  }

  // ------------------------------------------------------------ actions
  function terminal(command) {
    Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", command])
  }

  function quote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'"
  }

  function primaryAction() {
    if (!installed) setup()
    else if (!connected) terminal(quote(setupScript) + " status")
    else if (!pinSet) terminal("sudo omapasskey pin set")
    else if (updateAvailable) setup()
    else terminal("omapasskey status; echo; omapasskey doctor")
  }

  function setup() { terminal(quote(setupScript) + " install") }
  function listPasskeys() { terminal("sudo omapasskey list") }
  function changePin() { terminal("sudo omapasskey pin change") }

  // ------------------------------------------------------------ plumbing
  function checkInstalled() {
    if (installCheck.running) return
    installCheck.command = ["test", "-x", daemonPath]
    installCheck.running = true
  }

  Process {
    id: installCheck
    running: false
    command: []
    onExited: function(exitCode) {
      root.installed = exitCode === 0
      root.installChecked = true
    }
  }

  Socket {
    id: socket
    path: root.socketPath
    connected: false
    parser: SplitParser {
      onRead: function(data) { root.handleLine(data) }
    }
    onConnectionStateChanged: {
      root.connected = socket.connected
      if (!socket.connected) root.prompt = null
    }
  }

  // Reconnects after the service restarts, and notices a fresh install.
  Timer {
    interval: 3000
    repeat: true
    running: !root.connected
    triggeredOnStart: true
    onTriggered: {
      root.checkInstalled()
      socket.connected = false
      socket.connected = true
    }
  }

  Timer {
    id: outcomeTimer
    interval: 1100
    onTriggered: { root.outcome = ""; root.outcomePrompt = null }
  }

  Timer {
    id: noteTimer
    interval: 2600
    onTriggered: root.note = null
  }

  Timer {
    id: winkTimer
    interval: 1500
    onTriggered: root.winking = false
  }

  PromptWindow {
    service: root
  }
}
