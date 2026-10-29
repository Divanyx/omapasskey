"""End-to-end test with a real, headless Firefox: a page calls the WebAuthn
API, Firefox talks CTAP2 over hidraw to omapasskeyd (test build, simulated
key press), and the PIN is typed into Firefox's own PIN prompt through
Marionette. Usage: python firefox_e2e.py [PIN]

Starts its own Firefox with a throwaway profile; a running Firefox is left
alone."""

import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

PIN = sys.argv[1] if len(sys.argv) > 1 else "hunter2-test"
HTTP_PORT = 8765
MARIONETTE_PORT = 2829

PAGE = b"""<!doctype html><meta charset=utf-8><title>Omapasskey test</title>
<body>Omapasskey WebAuthn test page</body>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):
        pass


class Marionette:
    def __init__(self, port):
        for _ in range(100):
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=180)
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise SystemExit("Marionette did not come up")
        self.buf = b""
        self.id = 0
        self._read()  # hello

    def _read(self):
        while b":" not in self.buf:
            self.buf += self.sock.recv(65536)
        n, rest = self.buf.split(b":", 1)
        n = int(n)
        while len(rest) < n:
            rest += self.sock.recv(65536)
        self.buf = rest[n:]
        return json.loads(rest[:n])

    def cmd(self, name, params=None):
        self.id += 1
        msg = json.dumps([0, self.id, name, params or {}]).encode()
        self.sock.sendall(str(len(msg)).encode() + b":" + msg)
        while True:
            resp = self._read()
            if resp[0] == 1 and resp[1] == self.id:
                if resp[2]:
                    raise RuntimeError(resp[2])
                return resp[3]


# Replaces Firefox's prompt helper: answers the PIN prompt with our PIN,
# picks the first account, and records every prompt type it sees.
CHROME_HOOK = r"""
let WebAuthnPromptHelper;
for (const url of ["moz-src:///toolkit/modules/WebAuthnPromptHelper.sys.mjs", "resource://gre/modules/WebAuthnPromptHelper.sys.mjs"]) {
  try { ({ WebAuthnPromptHelper } = ChromeUtils.importESModule(url)); break; } catch (e) {}
}
const svc = Cc["@mozilla.org/webauthn/service;1"].getService(Ci.nsIWebAuthnService);
const pin = arguments[0];
globalThis.__omapasskeyPrompts = [];
// Firefox registers the helper through a lazy proxy, so its observe() is
// replaced in place: the PIN goes in, the first account is picked.
WebAuthnPromptHelper.observe = function (subject, topic, data) {
  if (topic != "webauthn-prompt") return;
  const d = JSON.parse(data);
  globalThis.__omapasskeyPrompts.push(d.prompt.type);
  if (d.prompt.type == "pin-required") svc.pinCallback(d.tid, pin);
  if (d.prompt.type == "pin-invalid") svc.cancel(d.tid);
  if (d.prompt.type == "select-sign-result") svc.selectionCallback(d.tid, 0);
  if (d.prompt.type == "attestation-consent") svc.setHasAttestationConsent(d.tid, false);
};
return "hooked";
"""

CEREMONY = r"""
const done = arguments[arguments.length - 1];
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
(async () => {
  const out = {};
  let t = performance.now();
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { id: "localhost", name: "Omapasskey test" },
    user: { id: new TextEncoder().encode("ff-" + Date.now()), name: "firefox-user", displayName: "Firefox User" },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    extensions: { credProps: true, prf: {} },
    timeout: 60000,
  }});
  out.createMs = Math.round(performance.now() - t);
  out.credId = cred.id;
  out.createExt = cred.getClientExtensionResults();
  out.transports = cred.response.getTransports ? cred.response.getTransports() : null;
  const authData = new Uint8Array(cred.response.getAuthenticatorData());
  out.createFlags = authData[32];

  t = performance.now();
  const got = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: "localhost",
    userVerification: "required",
    extensions: { prf: { eval: { first: new TextEncoder().encode("omapasskey") } } },
    timeout: 60000,
  }});
  out.getMs = Math.round(performance.now() - t);
  out.getId = got.id;
  out.userHandle = new TextDecoder().decode(got.response.userHandle);
  out.getFlags = new Uint8Array(got.response.authenticatorData)[32];
  const prf = got.getClientExtensionResults().prf;
  out.prf = prf && prf.results ? b64(prf.results.first) : null;

  // A 2FA-style request with an allow list and "discouraged" UV.
  t = performance.now();
  const second = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: "localhost",
    allowCredentials: [{ type: "public-key", id: got.rawId }],
    userVerification: "discouraged",
    timeout: 60000,
  }});
  out.allowListMs = Math.round(performance.now() - t);
  out.allowListFlags = new Uint8Array(second.response.authenticatorData)[32];
  return out;
})().then((o) => done({ ok: true, ...o }), (e) => done({ ok: false, error: e.name + ": " + e.message }));
"""


def main():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    profile = tempfile.mkdtemp(prefix="omapasskey-ff-")
    with open(os.path.join(profile, "user.js"), "w") as f:
        f.write(f'user_pref("marionette.port", {MARIONETTE_PORT});\n')
        f.write('user_pref("security.webauth.webauthn_enable_softtoken", false);\n')
        f.write('user_pref("security.webauth.webauthn_enable_usbtoken", true);\n')
        f.write('user_pref("browser.shell.checkDefaultBrowser", false);\n')
        f.write('user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
    env = dict(os.environ, MOZ_HEADLESS="1")
    ff = subprocess.Popen(["firefox", "--headless", "--marionette", "-remote-allow-system-access", "--no-remote", "--profile", profile],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        m = Marionette(MARIONETTE_PORT)
        m.cmd("WebDriver:NewSession", {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": True}}})
        m.cmd("Marionette:SetContext", {"value": "chrome"})
        print("hook:", m.cmd("WebDriver:ExecuteScript", {"script": CHROME_HOOK, "args": [PIN]})["value"])
        m.cmd("Marionette:SetContext", {"value": "content"})
        m.cmd("WebDriver:SetTimeouts", {"script": 180000})
        m.cmd("WebDriver:Navigate", {"url": f"http://localhost:{HTTP_PORT}/"})
        result = m.cmd("WebDriver:ExecuteAsyncScript", {"script": CEREMONY, "args": []})["value"]
        print(json.dumps(result, indent=1))
        m.cmd("Marionette:SetContext", {"value": "chrome"})
        prompts = m.cmd("WebDriver:ExecuteScript", {"script": "return globalThis.__omapasskeyPrompts;"})["value"]
        print("Firefox prompts:", prompts)
        version = subprocess.run(["firefox", "--version"], capture_output=True, text=True).stdout.strip()
        if not result.get("ok"):
            raise SystemExit(f"FAILED on {version}")
        assert result["createFlags"] & 0x05 == 0x05 and result["getFlags"] & 0x05 == 0x05
        assert result["allowListFlags"] & 0x05 == 0x05, "alwaysUv: discouraged UV must still verify"
        assert result["createExt"].get("credProps", {}).get("rk") is True
        assert result["prf"], "PRF output missing"
        print(f"ALL OK with {version}")
    finally:
        ff.terminate()
        try:
            ff.wait(10)
        except subprocess.TimeoutExpired:
            ff.kill()
        httpd.shutdown()
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    main()
