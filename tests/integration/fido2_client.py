"""End-to-end test of a running omapasskeyd (test build, simulated presence)
through Yubico's python-fido2 — an independent CTAP2 client and WebAuthn
relying party. Usage: python fido2_client.py /dev/hidrawN"""

import sys
import time

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2, CredentialManagement
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

PIN = "hunter2-test"
path = sys.argv[1]
dev = next(d for d in CtapHidDevice.list_devices() if d.descriptor.path == path)
ctap = Ctap2(dev)
info = ctap.info
print("getInfo:", info.versions, info.extensions, dict(info.options), "protocols", info.pin_uv_protocols)
assert info.options.get("alwaysUv") is True and info.options.get("credMgmt") is True
assert str(info.aaguid) == "2bfb6aa2-0b2f-4a8c-9e2a-6f6d61706b79"

client_pin = ClientPin(ctap)
if not info.options.get("clientPin"):
    client_pin.set_pin(PIN)
    print("PIN set")
print("retries:", client_pin.get_pin_retries())


class Interaction(UserInteraction):
    def __init__(self):
        self.pin_asked = 0

    def prompt_up(self):
        pass

    def request_pin(self, permissions, rp_id):
        self.pin_asked += 1
        return PIN

    def request_uv(self, permissions, rp_id):
        return True


ui = Interaction()
client = Fido2Client(dev, DefaultClientDataCollector("https://example.com"), user_interaction=ui)
server = Fido2Server(PublicKeyCredentialRpEntity(name="Example", id="example.com"), attestation="direct")


def register(name, rk, uv, prf=False):
    user = PublicKeyCredentialUserEntity(id=name.encode(), name=name, display_name=name.title())
    options, state = server.register_begin(
        user, resident_key_requirement=rk, user_verification=uv,
        extensions={"prf": {}} if prf else None)
    t0 = time.time()
    result = client.make_credential(options["publicKey"])
    took = time.time() - t0
    auth_data = server.register_complete(state, result)
    cred = auth_data.credential_data
    print(f"registered {name}: rk={rk.value} uv={uv.value} flags={auth_data.flags:#04x} in {took:.2f}s "
          f"ext={result.client_extension_results}")
    assert auth_data.flags & 0x05 == 0x05, "UP and UV must be set"
    return cred


alice = register("alice", ResidentKeyRequirement.REQUIRED, UserVerificationRequirement.REQUIRED, prf=True)
bob = register("bob", ResidentKeyRequirement.REQUIRED, UserVerificationRequirement.PREFERRED)
# A 2FA-style registration that does not ask for UV still gets it (alwaysUv).
carol = register("carol", ResidentKeyRequirement.DISCOURAGED, UserVerificationRequirement.DISCOURAGED)
creds = [alice, bob, carol]

# Re-registering alice is refused through the exclude list.
try:
    user = PublicKeyCredentialUserEntity(id=b"alice", name="alice", display_name="Alice")
    options, state = server.register_begin(user, credentials=[alice], resident_key_requirement=ResidentKeyRequirement.REQUIRED)
    client.make_credential(options["publicKey"])
    raise SystemExit("exclude list ignored")
except Exception as e:  # noqa: BLE001
    print("exclude list:", type(e).__name__, getattr(getattr(e, "cause", None), "code", ""))

# Passkey sign-in without a username: two accounts, newest first.
options, state = server.authenticate_begin(user_verification=UserVerificationRequirement.REQUIRED)
t0 = time.time()
selection = client.get_assertion(options["publicKey"])
took = time.time() - t0
responses = [selection.get_response(i) for i in range(len(selection.get_assertions()))]
names = [r.response.user_handle for r in responses]
print(f"discoverable sign-in: {len(responses)} accounts {names} in {took:.2f}s")
assert names == [b"bob", b"alice"], names
for r in responses:
    server.authenticate_complete(state, creds, r)
print("both assertions verify")

# Sign-in with an allow list (the 2FA credential).
options, state = server.authenticate_begin([carol], user_verification=UserVerificationRequirement.DISCOURAGED)
r = client.get_assertion(options["publicKey"]).get_response(0)
server.authenticate_complete(state, creds, r)
print("allow-list sign-in verifies, flags", hex(r.response.authenticator_data.flags))

# PRF (hmac-secret): stable per input, different across inputs.
def prf(first):
    options, state = server.authenticate_begin([alice], extensions={"prf": {"eval": {"first": first}}})
    r = client.get_assertion(options["publicKey"]).get_response(0)
    server.authenticate_complete(state, creds, r)
    return websafe_decode(r.client_extension_results["prf"]["results"]["first"])

a1, a2, b1 = prf(b"salt one"), prf(b"salt one"), prf(b"salt two")
assert a1 == a2 and a1 != b1 and len(a1) == 32
print("PRF ok:", a1[:8].hex(), b1[:8].hex())

# Credential management, as Firefox's about:webauthn does it.
token = client_pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
cm = CredentialManagement(ctap, client_pin.protocol, token)
meta = cm.get_metadata()
rps = cm.enumerate_rps()
accounts = cm.enumerate_creds(rps[0][CredentialManagement.RESULT.RP_ID_HASH])
print("credMgmt:", meta, [rp[CredentialManagement.RESULT.RP]["id"] for rp in rps],
      [a[CredentialManagement.RESULT.USER]["name"] for a in accounts])
cm.delete_cred(accounts[0][CredentialManagement.RESULT.CREDENTIAL_ID])
assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
print("deleted one passkey")

# A wrong PIN costs a retry and fails; the right one restores the counter.
try:
    client_pin.get_pin_token("wrong-pin-123", ClientPin.PERMISSION.GET_ASSERTION, "example.com")
    raise SystemExit("wrong PIN accepted")
except CtapError as e:
    print("wrong PIN:", e.code.name, "retries", client_pin.get_pin_retries())
client_pin.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, "example.com")
assert client_pin.get_pin_retries()[0] == 8
print("PIN asked by the client:", ui.pin_asked, "times")
print("ALL OK")
