package ctap2

import (
	"crypto/rand"
	"time"

	"github.com/Divanyx/omapasskey/internal/pinuv"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// pinUvAuthToken permissions.
const (
	permMC   = 0x01
	permGA   = 0x02
	permCM   = 0x04
	permBE   = 0x08
	permLBW  = 0x10
	permACFG = 0x20
)

const (
	// The platform must use a fresh token within this time, and each use
	// extends it by the same amount (rolling timer) ...
	tokenInitialLimit = 30 * time.Second
	// ... up to this ceiling.
	tokenMaxUsage = 10 * time.Minute
	// The physical confirmation collected with the PIN stays valid this long.
	userPresentLimit = 30 * time.Second
)

// token is the one pinUvAuthToken in use. It also carries the vault secrets
// the PIN unlocked; they are wiped the moment the token stops being in use.
type token struct {
	value        []byte
	protocol     pinuv.Protocol
	permissions  uint64
	rpID         string
	hasRPID      bool
	userPresent  bool
	presentAt    time.Time
	userVerified bool
	issued       time.Time
	lastUse      time.Time
	unlocked     *vault.Unlocked
	timer        *time.Timer
}

// beginToken creates a fresh token, invalidating any previous one.
func (a *Authenticator) beginToken(p pinuv.Protocol, perms uint64, rpID string, hasRPID bool, u *vault.Unlocked, userPresent bool) ([]byte, error) {
	a.stopToken()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	now := time.Now()
	t := &token{
		value: value, protocol: p, permissions: perms, rpID: rpID, hasRPID: hasRPID,
		userPresent: userPresent, presentAt: now, userVerified: true,
		issued: now, lastUse: now, unlocked: u,
	}
	t.timer = time.AfterFunc(tokenInitialLimit, func() { a.expireToken(t) })
	a.tok = t
	return value, nil
}

func (a *Authenticator) expireToken(t *token) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok == t && !t.valid(time.Now()) {
		a.stopToken()
	}
}

func (t *token) valid(now time.Time) bool {
	return now.Sub(t.issued) < tokenMaxUsage && now.Sub(t.lastUse) < tokenInitialLimit
}

// current returns the token if it is still in use.
func (a *Authenticator) current() *token {
	t := a.tok
	if t == nil {
		return nil
	}
	if !t.valid(time.Now()) {
		a.stopToken()
		return nil
	}
	return t
}

func (a *Authenticator) stopToken() {
	if a.tok == nil {
		return
	}
	a.tok.timer.Stop()
	clear(a.tok.value)
	a.tok.unlocked.Wipe()
	a.tok = nil
	// Paged credential-management results were decrypted under this token;
	// they end with it.
	a.enumRPs, a.enumCreds = nil, nil
}

// verifyToken checks pinUvAuthParam = authenticate(token, message) for the
// protocol the platform names, and marks the token used.
func (a *Authenticator) verifyToken(protocol uint64, message, param []byte) (*token, error) {
	t := a.current()
	if t == nil || t.protocol.Version() != protocol {
		return nil, Error(ErrPINAuthInvalid)
	}
	if !t.protocol.Verify(t.value, message, param) {
		return nil, Error(ErrPINAuthInvalid)
	}
	t.lastUse = time.Now()
	t.timer.Reset(tokenInitialLimit)
	return t, nil
}

// present reports the token's userPresent flag, honouring its time limit.
func (t *token) present() bool {
	return t.userPresent && time.Since(t.presentAt) < userPresentLimit
}

// consumeToken ends the token after an operation that tested user presence:
// the spec clears its flags and every permission but lbw, which this
// authenticator never grants, so nothing is left to use it for.
func (a *Authenticator) consumeToken() {
	a.stopToken()
}
