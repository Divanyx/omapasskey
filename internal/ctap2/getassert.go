package ctap2

import (
	"bytes"
	"crypto/sha256"
	"time"

	"github.com/Divanyx/omapasskey/internal/pinuv"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// A well-formed ECDSA signature (r = s = 1) that verifies under no key. It
// answers silent probes made without the PIN: the platform only learns that
// the credential exists, and nobody can turn a silent assertion into a login.
var nullSignature = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}

const nextAssertionTimeout = 30 * time.Second

// hmacInput is a validated hmac-secret request.
type hmacInput struct {
	proto  pinuv.Protocol
	secret []byte
	salts  [][]byte
}

// assertCtx is what every assertion of one request shares.
type assertCtx struct {
	rpID           string
	hash           []byte
	clientDataHash []byte
	up, uv         bool
	unlocked       *vault.Unlocked
	hmac           *hmacInput
}

type pendingAssertion struct {
	ctx   *assertCtx
	creds []*vault.Credential
	next  int
	timer *time.Timer
}

func (a *Authenticator) dropPending() {
	if a.pending == nil {
		return
	}
	a.pending.timer.Stop()
	a.pending.ctx.wipe()
	a.pending = nil
}

func (c *assertCtx) wipe() {
	c.unlocked.Wipe()
	if c.hmac != nil {
		clear(c.hmac.secret)
	}
}

func (a *Authenticator) getAssertion(r *request, params []byte) (any, error) {
	m, err := parseIntMap(params)
	if err != nil {
		return nil, err
	}
	rpID, ok, err := m.text(1)
	if err != nil {
		return nil, err
	}
	clientDataHash, ok2, err := m.bytes(2)
	if err != nil {
		return nil, err
	}
	if !ok || !ok2 {
		return nil, Error(ErrMissingParameter)
	}
	allowRaw, hasAllow, err := m.array(3)
	if err != nil {
		return nil, err
	}
	allow, err := parseDescriptors(allowRaw)
	if err != nil {
		return nil, err
	}
	extMap, _, err := m.strMap(4)
	if err != nil {
		return nil, err
	}
	optMap, _, err := m.strMap(5)
	if err != nil {
		return nil, err
	}
	opts, err := options(optMap)
	if err != nil {
		return nil, err
	}
	pinUvAuthParam, hasParam, err := m.bytes(6)
	if err != nil {
		return nil, err
	}
	protocol, hasProtocol, err := m.uint(7)
	if err != nil {
		return nil, err
	}

	if hasParam && len(pinUvAuthParam) == 0 {
		if err := a.confirm(r, Prompt{Op: "select"}, false); err != nil {
			return nil, err
		}
		a.selectedAt = time.Now()
		if a.vault.PINSet() {
			return nil, Error(ErrPINInvalid)
		}
		return nil, Error(ErrPINNotSet)
	}
	if hasParam {
		if !hasProtocol {
			return nil, Error(ErrMissingParameter)
		}
		if pinuv.ByVersion(protocol) == nil {
			return nil, Error(ErrInvalidParameter)
		}
	}
	if opts["uv"] && !hasParam {
		return nil, Error(ErrInvalidOption)
	}
	if _, ok := opts["rk"]; ok {
		return nil, Error(ErrUnsupportedOption)
	}
	up := true
	if v, ok := opts["up"]; ok {
		up = v
	}
	// alwaysUv: an assertion that tests presence always needs the PIN.
	if up && (!a.vault.PINSet() || !hasParam) {
		return nil, Error(ErrPUATRequired)
	}
	if len(clientDataHash) != 32 {
		return nil, Error(ErrInvalidLength)
	}

	ac := &assertCtx{rpID: rpID, hash: rpHash(rpID), clientDataHash: clientDataHash, up: up}
	keep := false
	defer func() {
		if !keep {
			ac.wipe()
		}
	}()
	present := false
	if hasParam {
		t, err := a.verifyToken(protocol, clientDataHash, pinUvAuthParam)
		if err != nil {
			return nil, err
		}
		if t.permissions&permGA == 0 || !t.userVerified {
			return nil, Error(ErrPINAuthInvalid)
		}
		if t.hasRPID && t.rpID != rpID {
			return nil, Error(ErrPINAuthInvalid)
		}
		if !t.hasRPID {
			t.rpID, t.hasRPID = rpID, true
		}
		ac.uv = true
		present = t.present()
		ac.unlocked = t.unlocked.Clone()
	}

	// hmac-secret is validated before anything is shown to the user.
	if raw, ok := extMap["hmac-secret"]; ok {
		if !up {
			return nil, Error(ErrUnsupportedOption)
		}
		in, err := a.parseHMACSecret(raw)
		if err != nil {
			return nil, err
		}
		ac.hmac = in
	}

	// Locate the applicable credentials.
	var creds []*vault.Credential
	if hasAllow && len(allow) > 0 {
		for _, d := range allow {
			if d.Type != "public-key" {
				continue
			}
			c := a.vault.Find(d.ID, ac.hash)
			if c == nil || containsCred(creds, c) {
				continue
			}
			if c.CredProtect == 3 && !ac.uv {
				continue
			}
			creds = append(creds, c)
		}
	} else if ac.uv {
		// Discovery without the PIN would tell any program which sites
		// have passkeys here, so it only happens with the PIN.
		for _, c := range a.vault.Discoverable(ac.hash) {
			creds = append(creds, c)
		}
	}
	if len(creds) == 0 {
		return nil, Error(ErrNoCredentials)
	}

	if up {
		if !present {
			if err := a.confirm(r, Prompt{Op: "sign-in", RPID: rpID}, false); err != nil {
				return nil, err
			}
		}
		a.consumeToken()
	}

	r.status(0x01)
	if hasAllow && len(allow) > 0 {
		resp, err := a.assertion(ac, creds[0], 0)
		if err != nil {
			return nil, err
		}
		a.finished(ac)
		return resp, nil
	}
	resp, err := a.assertion(ac, creds[0], len(creds))
	if err != nil {
		return nil, err
	}
	if len(creds) > 1 {
		p := &pendingAssertion{ctx: ac, creds: creds, next: 1}
		p.timer = time.AfterFunc(nextAssertionTimeout, func() { a.expirePending(p) })
		a.pending = p
		keep = true
	}
	a.finished(ac)
	return resp, nil
}

func (a *Authenticator) finished(ac *assertCtx) {
	if a.events != nil && ac.up {
		a.events.Done("sign-in", ac.rpID, true)
	}
}

func (a *Authenticator) expirePending(p *pendingAssertion) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == p {
		a.dropPending()
	}
}

func (a *Authenticator) getNextAssertion() (any, error) {
	p := a.pending
	if p == nil || p.next >= len(p.creds) {
		a.dropPending()
		return nil, Error(ErrNotAllowed)
	}
	c := p.creds[p.next]
	p.next++
	resp, err := a.assertion(p.ctx, c, 0)
	if err != nil {
		return nil, err
	}
	if p.next >= len(p.creds) {
		a.dropPending()
	} else {
		p.timer.Reset(nextAssertionTimeout)
	}
	return resp, nil
}

// assertion builds one response. count > 1 adds numberOfCredentials.
func (a *Authenticator) assertion(ac *assertCtx, c *vault.Credential, count int) (map[int]any, error) {
	var flags byte
	if ac.up {
		flags |= flagUP
	}
	if ac.uv {
		flags |= flagUV
	}
	var ext []byte
	if ac.hmac != nil && c.HMACKey != nil && ac.unlocked != nil {
		out, err := a.hmacSecret(ac, c)
		if err != nil {
			return nil, err
		}
		ext = encode(map[string]any{"hmac-secret": out})
		flags |= flagED
	}
	authData := make([]byte, 0, 37+len(ext))
	authData = append(authData, ac.hash...)
	authData = append(authData, flags, 0, 0, 0, 0)
	authData = append(authData, ext...)

	sig := nullSignature
	if ac.unlocked != nil {
		digest := sha256.Sum256(append(append([]byte(nil), authData...), ac.clientDataHash...))
		s, err := a.sign(ac.unlocked, c, digest[:])
		if err != nil {
			return nil, Error(ErrOther)
		}
		sig = s
	}
	resp := map[int]any{
		1: map[string]any{"id": c.ID, "type": "public-key"},
		2: authData,
		3: sig,
	}
	if c.Discoverable && ac.unlocked != nil {
		acct, err := a.vault.Account(ac.unlocked, c)
		if err != nil {
			return nil, Error(ErrOther)
		}
		user := map[string]any{"id": acct.UserID}
		// Names only with user verification, as the spec requires.
		if ac.uv {
			if acct.UserName != "" {
				user["name"] = acct.UserName
			}
			if acct.DisplayName != "" {
				user["displayName"] = acct.DisplayName
			}
		}
		resp[4] = user
	}
	if count > 1 {
		resp[5] = count
	}
	return resp, nil
}

func (a *Authenticator) parseHMACSecret(raw []byte) (*hmacInput, error) {
	var m intMap
	if err := decodeRaw(raw, majorMap, &m); err != nil {
		return nil, err
	}
	version := uint64(1)
	if v, ok, err := m.uint(4); err != nil {
		return nil, err
	} else if ok {
		version = v
	}
	proto := pinuv.ByVersion(version)
	if proto == nil {
		return nil, Error(ErrInvalidParameter)
	}
	saltEnc, ok1, err := m.bytes(2)
	if err != nil {
		return nil, err
	}
	saltAuth, ok2, err := m.bytes(3)
	if err != nil {
		return nil, err
	}
	if !ok1 || !ok2 {
		return nil, Error(ErrMissingParameter)
	}
	secret, err := a.sharedSecret(m, 1, proto)
	if err != nil {
		return nil, err
	}
	if !proto.Verify(secret, saltEnc, saltAuth) {
		clear(secret)
		return nil, Error(ErrPINAuthInvalid)
	}
	salts, err := proto.Decrypt(secret, saltEnc)
	if err != nil || (len(salts) != 32 && len(salts) != 64) {
		clear(secret)
		return nil, Error(ErrInvalidParameter)
	}
	in := &hmacInput{proto: proto, secret: secret, salts: [][]byte{salts[:32]}}
	if len(salts) == 64 {
		in.salts = append(in.salts, salts[32:])
	}
	return in, nil
}

// hmacSecret computes the encrypted hmac-secret output. The TPM key plays
// the role of CredRandom; a prefix separates the with-UV and without-UV
// secrets the spec asks for.
func (a *Authenticator) hmacSecret(ac *assertCtx, c *vault.Credential) ([]byte, error) {
	prefix := []byte("omapasskey/hmac-secret/no-uv\x00")
	if ac.uv {
		prefix = []byte("omapasskey/hmac-secret/uv\x00")
	}
	var out []byte
	for _, salt := range ac.hmac.salts {
		v, err := a.vault.HMAC(ac.unlocked, c, append(append([]byte(nil), prefix...), salt...))
		if err != nil {
			return nil, Error(ErrOther)
		}
		out = append(out, v...)
	}
	enc, err := ac.hmac.proto.Encrypt(ac.hmac.secret, out)
	clear(out)
	if err != nil {
		return nil, Error(ErrOther)
	}
	return enc, nil
}

func containsCred(list []*vault.Credential, c *vault.Credential) bool {
	for _, x := range list {
		if bytes.Equal(x.ID, c.ID) {
			return true
		}
	}
	return false
}
