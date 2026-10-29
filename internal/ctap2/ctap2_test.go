package ctap2

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/Divanyx/omapasskey/internal/pinuv"
	"github.com/Divanyx/omapasskey/internal/tpm"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// fakePresence counts confirmations and can refuse them.
type fakePresence struct {
	n      int
	refuse bool
	ops    []string
}

func (f *fakePresence) Confirm(ctx context.Context, p Prompt) error {
	f.n++
	f.ops = append(f.ops, p.Op+":"+p.RPID)
	if f.refuse {
		return ErrPresenceDenied
	}
	return nil
}

type statusEvents struct{ a *Authenticator }

func (e *statusEvents) Done(op, rpID string, ok bool) { e.a.AdminStatus() }
func (e *statusEvents) Wink()                         {}
func (e *statusEvents) StateChanged()                 { e.a.AdminStatus() }

type harness struct {
	t    *testing.T
	a    *Authenticator
	pres *fakePresence
	v    *vault.Vault
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	// The reference simulator locks out after three wrong guesses; give it
	// the generous settings of real TPMs so the CTAP counters are tested.
	lockoutAuth := []byte{0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00}
	params := append([]byte{0x80, 0x02, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x01, 0x3A, 0x40, 0x00, 0x00, 0x0A}, lockoutAuth...)
	params = append(params, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0)
	if rsp, err := sim.Send(params); err != nil || !bytes.Equal(rsp[6:10], []byte{0, 0, 0, 0}) {
		t.Fatalf("DictionaryAttackParameters: %x %v", rsp, err)
	}
	k, err := tpm.New(sim)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close() })
	v, err := vault.Open(filepath.Join(t.TempDir(), "state.json"), k)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakePresence{}
	a, err := New(Config{AAGUID: [16]byte{1, 2, 3}, MinPINLength: 6, Firmware: 1}, v, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Event handlers read the status back, as the daemon's do; a command
	// that holds the lock while it notifies must not deadlock.
	a.events = &statusEvents{a: a}
	return &harness{t: t, a: a, pres: p, v: v}
}

// do sends one command and returns status and decoded response.
func (h *harness) do(cmd byte, params any) (byte, map[int]cbor.RawMessage) {
	h.t.Helper()
	msg := []byte{cmd}
	if params != nil {
		msg = append(msg, encode(params)...)
	}
	resp := h.a.CBOR(context.Background(), msg, func(byte) {})
	if resp[0] != 0 || len(resp) == 1 {
		return resp[0], nil
	}
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(resp[1:], &m); err != nil {
		h.t.Fatalf("bad response CBOR: %v", err)
	}
	return 0, m
}

func (h *harness) must(cmd byte, params any) map[int]cbor.RawMessage {
	h.t.Helper()
	st, m := h.do(cmd, params)
	if st != 0 {
		h.t.Fatalf("command 0x%02x failed with status 0x%02x", cmd, st)
	}
	return m
}

// platform side of PIN/UV auth protocol 2.
type platform struct {
	proto  pinuv.Protocol
	key    *ecdh.PrivateKey
	secret []byte
}

func (h *harness) agree(version uint64) *platform {
	h.t.Helper()
	m := h.must(cmdClientPIN, map[int]any{1: version, 2: pinGetKeyAgreement})
	var cose map[int]cbor.RawMessage
	cbor.Unmarshal(m[1], &cose)
	var x, y []byte
	cbor.Unmarshal(cose[-2], &x)
	cbor.Unmarshal(cose[-3], &y)
	peer, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	if err != nil {
		h.t.Fatal(err)
	}
	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	z, _ := key.ECDH(peer)
	p := pinuv.ByVersion(version)
	secret, _ := p.KDF(z)
	return &platform{proto: p, key: key, secret: secret}
}

func (p *platform) cose() map[int]any {
	raw := p.key.PublicKey().Bytes()
	return map[int]any{1: 2, 3: -25, -1: 1, -2: raw[1:33], -3: raw[33:]}
}

func (h *harness) setPIN(pin string) {
	h.t.Helper()
	p := h.agree(2)
	padded := make([]byte, 64)
	copy(padded, pin)
	enc, _ := p.proto.Encrypt(p.secret, padded)
	h.must(cmdClientPIN, map[int]any{1: 2, 2: pinSetPIN, 3: p.cose(), 4: p.proto.Authenticate(p.secret, enc), 5: enc})
}

func pinHashEnc(p *platform, pin string) []byte {
	sum := sha256.Sum256([]byte(pin))
	enc, _ := p.proto.Encrypt(p.secret, sum[:16])
	return enc
}

// token obtains a pinUvAuthToken with permissions.
func (h *harness) token(pin string, perms uint64, rpID string) (byte, []byte, *platform) {
	h.t.Helper()
	p := h.agree(2)
	params := map[int]any{1: 2, 2: pinGetTokenWithPerms, 3: p.cose(), 6: pinHashEnc(p, pin), 9: perms}
	if rpID != "" {
		params[10] = rpID
	}
	st, m := h.do(cmdClientPIN, params)
	if st != 0 {
		return st, nil, p
	}
	var enc []byte
	cbor.Unmarshal(m[2], &enc)
	tok, err := p.proto.Decrypt(p.secret, enc)
	if err != nil {
		h.t.Fatal(err)
	}
	return 0, tok, p
}

func cdh(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

type registered struct {
	id     []byte
	pubX   *big.Int
	pubY   *big.Int
	flags  byte
	ext    map[string]cbor.RawMessage
	aaguid []byte
}

func parseAuthData(t *testing.T, ad []byte) registered {
	t.Helper()
	var r registered
	r.flags = ad[32]
	rest := ad[37:]
	if r.flags&flagAT != 0 {
		r.aaguid = rest[:16]
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		r.id = rest[18 : 18+n]
		rest = rest[18+n:]
		var key map[int]cbor.RawMessage
		rest2, err := cbor.UnmarshalFirst(rest, &key)
		if err != nil {
			t.Fatal(err)
		}
		var kx, ky []byte
		var kty, alg, crv int
		cbor.Unmarshal(key[1], &kty)
		cbor.Unmarshal(key[3], &alg)
		cbor.Unmarshal(key[-1], &crv)
		cbor.Unmarshal(key[-2], &kx)
		cbor.Unmarshal(key[-3], &ky)
		if kty != 2 || alg != -7 || crv != 1 || len(key) != 5 {
			t.Fatalf("bad COSE key %v", key)
		}
		r.pubX, r.pubY = new(big.Int).SetBytes(kx), new(big.Int).SetBytes(ky)
		rest = rest2
	}
	if r.flags&flagED != 0 {
		if err := cbor.Unmarshal(rest, &r.ext); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func verifySig(t *testing.T, x, y *big.Int, authData, clientDataHash, sig []byte) {
	t.Helper()
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	d := sha256.Sum256(append(append([]byte(nil), authData...), clientDataHash...))
	if !ecdsa.VerifyASN1(pub, d[:], sig) {
		t.Fatal("signature does not verify")
	}
}

func (h *harness) makeCred(pin, rpID string, userID []byte, name string, rk bool, ext map[string]any) registered {
	h.t.Helper()
	st, tok, p := h.token(pin, permMC|permGA, rpID)
	if st != 0 {
		h.t.Fatalf("token: 0x%02x", st)
	}
	hash := cdh("register " + name)
	params := map[int]any{
		1: hash,
		2: map[string]any{"id": rpID, "name": "Example"},
		3: map[string]any{"id": userID, "name": name, "displayName": "Display " + name},
		4: []map[string]any{{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}},
		7: map[string]bool{"rk": rk},
		8: p.proto.Authenticate(tok, hash),
		9: 2,
	}
	if ext != nil {
		params[6] = ext
	}
	m := h.must(cmdMakeCredential, params)
	var fmtName string
	var authData []byte
	var att map[string]cbor.RawMessage
	cbor.Unmarshal(m[1], &fmtName)
	cbor.Unmarshal(m[2], &authData)
	cbor.Unmarshal(m[3], &att)
	if fmtName != "packed" {
		h.t.Fatalf("fmt %q", fmtName)
	}
	r := parseAuthData(h.t, authData)
	if r.flags&(flagUP|flagUV|flagAT) != flagUP|flagUV|flagAT {
		h.t.Fatalf("flags %08b", r.flags)
	}
	var sig []byte
	cbor.Unmarshal(att["sig"], &sig)
	verifySig(h.t, r.pubX, r.pubY, authData, hash, sig)
	if !bytes.Equal(authData[:32], cdh(rpID)) {
		h.t.Fatal("rpIdHash")
	}
	return r
}

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)

	// Fresh: no PIN, so nothing can be created.
	var info map[int]cbor.RawMessage
	info = h.must(cmdGetInfo, nil)
	var opts map[string]bool
	cbor.Unmarshal(info[4], &opts)
	if opts["clientPin"] || !opts["alwaysUv"] || !opts["pinUvAuthToken"] || !opts["credMgmt"] {
		t.Fatalf("options %v", opts)
	}

	// Too short a PIN is refused; a good one is accepted after a key press.
	p := h.agree(2)
	padded := make([]byte, 64)
	copy(padded, "1234")
	enc, _ := p.proto.Encrypt(p.secret, padded)
	if st, _ := h.do(cmdClientPIN, map[int]any{1: 2, 2: pinSetPIN, 3: p.cose(), 4: p.proto.Authenticate(p.secret, enc), 5: enc}); st != ErrPINPolicyViolation {
		t.Fatalf("short PIN: 0x%02x", st)
	}
	before := h.pres.n
	h.setPIN("hunter22")
	if h.pres.n != before+1 {
		t.Fatal("setting the PIN did not ask for a key press")
	}
	info = h.must(cmdGetInfo, nil)
	cbor.Unmarshal(info[4], &opts)
	if !opts["clientPin"] {
		t.Fatal("clientPin not reported after setPIN")
	}

	// alwaysUv: without the PIN there is no registration and no sign-in.
	if st, _ := h.do(cmdMakeCredential, map[int]any{
		1: cdh("x"), 2: map[string]any{"id": "example.com"},
		3: map[string]any{"id": []byte{1}}, 4: []map[string]any{{"type": "public-key", "alg": -7}},
	}); st != ErrPUATRequired {
		t.Fatalf("makeCredential without PIN: 0x%02x", st)
	}

	// One key press per ceremony: the one taken with the PIN.
	before = h.pres.n
	alice := h.makeCred("hunter22", "example.com", []byte("alice-id"), "alice", true, map[string]any{"hmac-secret": true, "credProtect": 2})
	if h.pres.n != before+1 {
		t.Fatalf("registration took %d key presses", h.pres.n-before)
	}
	if string(alice.ext["hmac-secret"]) != "\xf5" {
		t.Fatalf("hmac-secret output %x", alice.ext["hmac-secret"])
	}
	bob := h.makeCred("hunter22", "example.com", []byte("bob-id"), "bob", true, nil)
	server := h.makeCred("hunter22", "example.com", []byte("carol-id"), "carol", false, nil)
	h.makeCred("hunter22", "other.org", []byte("alice-id"), "alice", true, nil)

	// Excluded credential: a second registration is refused.
	{
		st, tok, p := h.token("hunter22", permMC|permGA, "example.com")
		if st != 0 {
			t.Fatal(st)
		}
		hash := cdh("again")
		st, _ = h.do(cmdMakeCredential, map[int]any{
			1: hash, 2: map[string]any{"id": "example.com"},
			3: map[string]any{"id": []byte("alice-id")},
			4: []map[string]any{{"type": "public-key", "alg": -7}},
			5: []map[string]any{{"type": "public-key", "id": alice.id}},
			8: p.proto.Authenticate(tok, hash), 9: 2,
		})
		if st != ErrCredentialExcluded {
			t.Fatalf("excluded: 0x%02x", st)
		}
	}

	// Silent probe without the PIN finds a listed credential but cannot sign.
	{
		st, m := h.do(cmdGetAssertion, map[int]any{
			1: "example.com", 2: cdh(""),
			3: []map[string]any{{"type": "public-key", "id": []byte("nope")}, {"type": "public-key", "id": server.id}},
			5: map[string]bool{"up": false},
		})
		if st != 0 {
			t.Fatalf("silent probe: 0x%02x", st)
		}
		var cred map[string]cbor.RawMessage
		cbor.Unmarshal(m[1], &cred)
		var id, sig []byte
		cbor.Unmarshal(cred["id"], &id)
		cbor.Unmarshal(m[3], &sig)
		if !bytes.Equal(id, server.id) || !bytes.Equal(sig, nullSignature) {
			t.Fatal("silent probe returned the wrong credential or a real signature")
		}
		// ... and never reveals discoverable credentials.
		if st, _ := h.do(cmdGetAssertion, map[int]any{1: "example.com", 2: cdh(""), 5: map[string]bool{"up": false}}); st != ErrNoCredentials {
			t.Fatalf("silent discovery: 0x%02x", st)
		}
	}

	// Sign-in with discoverable credentials: newest first, then the rest.
	{
		st, tok, p := h.token("hunter22", permGA, "example.com")
		if st != 0 {
			t.Fatal(st)
		}
		hash := cdh("login")
		param := p.proto.Authenticate(tok, hash)
		// The browser's preflight with the token must not consume it.
		if st, _ := h.do(cmdGetAssertion, map[int]any{
			1: "example.com", 2: hash, 3: []map[string]any{{"type": "public-key", "id": bob.id}},
			5: map[string]bool{"up": false}, 6: param, 7: 2,
		}); st != 0 {
			t.Fatalf("preflight with token: 0x%02x", st)
		}
		before := h.pres.n
		m := h.must(cmdGetAssertion, map[int]any{1: "example.com", 2: hash, 6: param, 7: 2})
		if h.pres.n != before {
			t.Fatal("sign-in asked for a second key press")
		}
		var count int
		cbor.Unmarshal(m[5], &count)
		if count != 2 {
			t.Fatalf("numberOfCredentials %d", count)
		}
		var authData, sig []byte
		var user map[string]cbor.RawMessage
		cbor.Unmarshal(m[2], &authData)
		cbor.Unmarshal(m[3], &sig)
		cbor.Unmarshal(m[4], &user)
		var uid []byte
		var uname string
		cbor.Unmarshal(user["id"], &uid)
		cbor.Unmarshal(user["name"], &uname)
		if string(uid) != "bob-id" || uname != "bob" {
			t.Fatalf("first account %q %q", uid, uname)
		}
		if authData[32] != flagUP|flagUV {
			t.Fatalf("assertion flags %08b", authData[32])
		}
		verifySig(t, bob.pubX, bob.pubY, authData, hash, sig)

		m = h.must(cmdGetNextAssertion, nil)
		cbor.Unmarshal(m[2], &authData)
		cbor.Unmarshal(m[3], &sig)
		verifySig(t, alice.pubX, alice.pubY, authData, hash, sig)
		if st, _ := h.do(cmdGetNextAssertion, nil); st != ErrNotAllowed {
			t.Fatalf("third getNextAssertion: 0x%02x", st)
		}
		// The token was used up by the sign-in.
		if st, _ := h.do(cmdGetAssertion, map[int]any{1: "example.com", 2: hash, 6: param, 7: 2}); st != ErrPINAuthInvalid {
			t.Fatalf("reused token: 0x%02x", st)
		}
	}

	// A token for one site cannot sign in to another.
	{
		_, tok, p := h.token("hunter22", permGA, "example.com")
		hash := cdh("x")
		if st, _ := h.do(cmdGetAssertion, map[int]any{1: "other.org", 2: hash, 6: p.proto.Authenticate(tok, hash), 7: 2}); st != ErrPINAuthInvalid {
			t.Fatalf("cross-site token: 0x%02x", st)
		}
	}

	// hmac-secret (PRF): stable per salt, different per salt, encrypted.
	prf := func(salt []byte) []byte {
		st, tok, p := h.token("hunter22", permGA, "example.com")
		if st != 0 {
			t.Fatal(st)
		}
		hash := cdh("prf")
		saltEnc, _ := p.proto.Encrypt(p.secret, salt)
		m := h.must(cmdGetAssertion, map[int]any{
			1: "example.com", 2: hash,
			3: []map[string]any{{"type": "public-key", "id": alice.id}},
			4: map[string]any{"hmac-secret": map[int]any{1: p.cose(), 2: saltEnc, 3: p.proto.Authenticate(p.secret, saltEnc), 4: 2}},
			6: p.proto.Authenticate(tok, hash), 7: 2,
		})
		var authData []byte
		cbor.Unmarshal(m[2], &authData)
		r := parseAuthData(t, authData)
		var out []byte
		cbor.Unmarshal(r.ext["hmac-secret"], &out)
		plain, err := p.proto.Decrypt(p.secret, out)
		if err != nil {
			t.Fatal(err)
		}
		return plain
	}
	s1 := bytes.Repeat([]byte{1}, 32)
	s2 := bytes.Repeat([]byte{2}, 32)
	a1, a2, b1 := prf(s1), prf(s1), prf(s2)
	if len(a1) != 32 || !bytes.Equal(a1, a2) || bytes.Equal(a1, b1) {
		t.Fatalf("PRF outputs unstable: %x %x %x", a1, a2, b1)
	}
	two := prf(append(append([]byte(nil), s1...), s2...))
	if !bytes.Equal(two[:32], a1) || !bytes.Equal(two[32:], b1) {
		t.Fatal("two-salt PRF output differs from single-salt outputs")
	}

	// Credential management: list RPs and accounts, rename, delete.
	{
		st, tok, p := h.token("hunter22", permCM, "")
		if st != 0 {
			t.Fatal(st)
		}
		auth := func(sub byte, params any) []byte {
			msg := []byte{sub}
			if params != nil {
				msg = append(msg, encode(params)...)
			}
			return p.proto.Authenticate(tok, msg)
		}
		m := h.must(cmdCredentialManagement, map[int]any{1: cmGetCredsMetadata, 3: 2, 4: auth(cmGetCredsMetadata, nil)})
		var existing int
		cbor.Unmarshal(m[1], &existing)
		if existing != 3 {
			t.Fatalf("discoverable count %d", existing)
		}
		m = h.must(cmdCredentialManagement, map[int]any{1: cmEnumerateRPsBegin, 3: 2, 4: auth(cmEnumerateRPsBegin, nil)})
		var total int
		cbor.Unmarshal(m[5], &total)
		if total != 2 {
			t.Fatalf("RPs %d", total)
		}
		h.must(cmdCredentialManagement, map[int]any{1: cmEnumerateRPsNext})
		sp := map[int]any{1: cdh("example.com")}
		m = h.must(cmdCredentialManagement, map[int]any{1: cmEnumerateCredsBegin, 2: sp, 3: 2, 4: auth(cmEnumerateCredsBegin, sp)})
		cbor.Unmarshal(m[9], &total)
		if total != 2 || m[8] == nil || m[10] == nil {
			t.Fatalf("credentials %d, publicKey %v credProtect %v", total, m[8] != nil, m[10] != nil)
		}
		del := map[int]any{2: map[string]any{"type": "public-key", "id": bob.id}}
		h.must(cmdCredentialManagement, map[int]any{1: cmDeleteCredential, 2: del, 3: 2, 4: auth(cmDeleteCredential, del)})
		if h.v.FindByID(bob.id) != nil {
			t.Fatal("bob still stored")
		}
	}

	// Wrong PINs: retries count down, three in a row block until "replug".
	for i := 0; i < 2; i++ {
		if st, _, _ := h.token("wrong-pin", permGA, "example.com"); st != ErrPINInvalid {
			t.Fatalf("wrong PIN %d: 0x%02x", i, st)
		}
	}
	if st, _, _ := h.token("wrong-pin", permGA, "example.com"); st != ErrPINAuthBlocked {
		t.Fatalf("third wrong PIN: 0x%02x", st)
	}
	if st, _, _ := h.token("hunter22", permGA, "example.com"); st != ErrPINAuthBlocked {
		t.Fatalf("blocked PIN entry: 0x%02x", st)
	}
	h.a.PowerCycle()
	if st, _, _ := h.token("hunter22", permGA, "example.com"); st != 0 {
		t.Fatalf("correct PIN after replug: 0x%02x", st)
	}
	if h.v.PINRetries() != vault.MaxPINRetries {
		t.Fatal("retries not restored")
	}

	// Refusing the key press refuses the PIN check without spending a retry.
	h.pres.refuse = true
	if st, _, _ := h.token("hunter22", permGA, "example.com"); st != ErrOperationDenied {
		t.Fatalf("refused presence: 0x%02x", st)
	}
	if h.v.PINRetries() != vault.MaxPINRetries {
		t.Fatal("a refused key press cost a PIN retry")
	}
	// ... and a reset needs the key press too.
	if st, _ := h.do(cmdReset, nil); st != ErrOperationDenied {
		t.Fatalf("reset without presence: 0x%02x", st)
	}
	h.pres.refuse = false
	h.must(cmdReset, nil)
	if h.v.PINSet() {
		t.Fatal("PIN survived reset")
	}
	if _, total := h.v.Counts(); total != 0 {
		t.Fatal("credentials survived reset")
	}
}

func TestChangePIN(t *testing.T) {
	h := newHarness(t)
	h.setPIN("hunter22")
	cred := h.makeCred("hunter22", "example.com", []byte("u"), "u", true, nil)

	p := h.agree(1) // protocol one on purpose
	padded := make([]byte, 64)
	copy(padded, "correct horse")
	newEnc, _ := p.proto.Encrypt(p.secret, padded)
	oldEnc := pinHashEnc(p, "hunter22")
	h.must(cmdClientPIN, map[int]any{1: 1, 2: pinChangePIN, 3: p.cose(), 4: p.proto.Authenticate(p.secret, append(append([]byte(nil), newEnc...), oldEnc...)), 5: newEnc, 6: oldEnc})

	if st, _, _ := h.token("hunter22", permGA, "example.com"); st != ErrPINInvalid {
		t.Fatalf("old PIN still works: 0x%02x", st)
	}
	st, tok, pp := h.token("correct horse", permGA, "example.com")
	if st != 0 {
		t.Fatalf("new PIN: 0x%02x", st)
	}
	// Credentials made under the old PIN still work under the new one.
	hash := cdh("after change")
	m := h.must(cmdGetAssertion, map[int]any{1: "example.com", 2: hash, 6: pp.proto.Authenticate(tok, hash), 7: 2})
	var authData, sig []byte
	cbor.Unmarshal(m[2], &authData)
	cbor.Unmarshal(m[3], &sig)
	verifySig(t, cred.pubX, cred.pubY, authData, hash, sig)
}

func TestVaultIsUselessWithoutPIN(t *testing.T) {
	h := newHarness(t)
	h.setPIN("hunter22")
	cred := h.makeCred("hunter22", "secret-bank.example", []byte("u"), "u", true, nil)
	c := h.v.FindByID(cred.id)
	// The stored metadata does not contain the site or the account in clear.
	for _, needle := range [][]byte{[]byte("secret-bank"), []byte("Display u")} {
		if bytes.Contains(c.Sealed, needle) {
			t.Fatal("metadata stored in clear")
		}
	}
	// A wrong PIN never yields the keys.
	if _, err := h.v.Unlock(bytes.Repeat([]byte{9}, 16)); err != vault.ErrWrongPIN {
		t.Fatalf("unlock with wrong PIN: %v", err)
	}
}
