package ctap2

import (
	"crypto/sha256"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/Divanyx/omapasskey/internal/pinuv"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// clientPIN subcommands.
const (
	pinGetRetries        = 0x01
	pinGetKeyAgreement   = 0x02
	pinSetPIN            = 0x03
	pinChangePIN         = 0x04
	pinGetToken          = 0x05
	pinGetTokenUV        = 0x06
	pinGetUVRetries      = 0x07
	pinGetTokenWithPerms = 0x09
)

// After three consecutive wrong PINs the spec demands a power cycle. A
// virtual key cannot be unplugged, so the block lifts by itself after this
// long; every attempt needs a physical key press anyway.
const pinAuthBlockDuration = 30 * time.Second

func (a *Authenticator) clientPIN(r *request, params []byte) (any, error) {
	m, err := parseIntMap(params)
	if err != nil {
		return nil, err
	}
	sub, ok, err := m.uint(2)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	switch sub {
	case pinGetRetries:
		return map[int]any{3: a.vault.PINRetries(), 4: a.authBlocked()}, nil
	case pinGetTokenUV, pinGetUVRetries:
		// There is no built-in user verification method.
		return nil, Error(ErrInvalidSubcommand)
	case pinGetKeyAgreement, pinSetPIN, pinChangePIN, pinGetToken, pinGetTokenWithPerms:
	default:
		return nil, Error(ErrInvalidSubcommand)
	}

	pv, ok, err := m.uint(1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	proto := pinuv.ByVersion(pv)
	if proto == nil {
		return nil, Error(ErrInvalidParameter)
	}
	switch sub {
	case pinGetKeyAgreement:
		return map[int]any{1: a.ka.COSE()}, nil
	case pinSetPIN:
		return a.setPIN(r, m, proto)
	case pinChangePIN:
		return a.changePIN(r, m, proto)
	}
	return a.getToken(r, m, proto, sub)
}

func (a *Authenticator) authBlocked() bool {
	if a.blockedAt.IsZero() {
		return false
	}
	if time.Since(a.blockedAt) >= pinAuthBlockDuration {
		a.blockedAt = time.Time{}
		a.consecutive = 0
		return false
	}
	return true
}

// sharedSecret decapsulates the platform's key agreement key (parameter 3).
func (a *Authenticator) sharedSecret(m intMap, key int, proto pinuv.Protocol) ([]byte, error) {
	cose, ok, err := m.intMap(key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	return a.decapsulate(cose, proto)
}

func (a *Authenticator) decapsulate(cose intMap, proto pinuv.Protocol) ([]byte, error) {
	x, _, err := cose.bytes(-2)
	if err != nil {
		return nil, Error(ErrInvalidParameter)
	}
	y, _, err := cose.bytes(-3)
	if err != nil {
		return nil, Error(ErrInvalidParameter)
	}
	secret, err := a.ka.SharedSecret(proto, x, y)
	if err != nil {
		return nil, Error(ErrInvalidParameter)
	}
	return secret, nil
}

// newPIN decrypts and checks newPinEnc. It returns LEFT(SHA-256(pin), 16)
// and the length in code points.
func (a *Authenticator) newPIN(proto pinuv.Protocol, secret, newPinEnc []byte) ([]byte, int, error) {
	padded, err := proto.Decrypt(secret, newPinEnc)
	if err != nil {
		return nil, 0, Error(ErrPINAuthInvalid)
	}
	defer clear(padded)
	if len(padded) != 64 {
		return nil, 0, Error(ErrInvalidParameter)
	}
	end := len(padded)
	for end > 0 && padded[end-1] == 0 {
		end--
	}
	pin := padded[:end]
	if len(pin) > 63 || !utf8.Valid(pin) {
		return nil, 0, Error(ErrPINPolicyViolation)
	}
	points := utf8.RuneCount(pin)
	if points < a.cfg.MinPINLength {
		return nil, 0, Error(ErrPINPolicyViolation)
	}
	h := sha256.Sum256(pin)
	return h[:16], points, nil
}

func (a *Authenticator) setPIN(r *request, m intMap, proto pinuv.Protocol) (any, error) {
	newPinEnc, ok1, err := m.bytes(5)
	if err != nil {
		return nil, err
	}
	param, ok2, err := m.bytes(4)
	if err != nil {
		return nil, err
	}
	if _, ok3 := m[3]; !ok1 || !ok2 || !ok3 {
		return nil, Error(ErrMissingParameter)
	}
	if a.vault.PINSet() {
		return nil, Error(ErrPINAuthInvalid)
	}
	secret, err := a.sharedSecret(m, 3, proto)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	if !proto.Verify(secret, newPinEnc, param) {
		return nil, Error(ErrPINAuthInvalid)
	}
	hash, points, err := a.newPIN(proto, secret, newPinEnc)
	if err != nil {
		return nil, err
	}
	// Whoever sets the PIN first owns the authenticator, so it takes a
	// physical key press: software alone can never claim it.
	if err := a.confirm(r, Prompt{Op: "set-pin"}, false); err != nil {
		return nil, err
	}
	if err := a.vault.SetPIN(hash, points); err != nil {
		return nil, Error(ErrOther)
	}
	a.consecutive = 0
	if a.events != nil {
		a.events.StateChanged()
	}
	return nil, nil
}

// checkPIN runs the shared part of every PIN verification: the physical
// confirmation first (so that software cannot burn PIN retries), then the
// retry counter, then the TPM.
func (a *Authenticator) checkPIN(r *request, proto pinuv.Protocol, secret, pinHashEnc []byte, prompt Prompt) (*vault.Unlocked, error) {
	if !a.vault.PINSet() {
		return nil, Error(ErrPINNotSet)
	}
	if a.vault.PINRetries() == 0 {
		return nil, Error(ErrPINBlocked)
	}
	if a.authBlocked() {
		return nil, Error(ErrPINAuthBlocked)
	}
	if !a.takeSelection() {
		if err := a.confirm(r, prompt, false); err != nil {
			return nil, err
		}
	}
	left, err := a.vault.ConsumePINRetry()
	if err != nil {
		return nil, Error(ErrOther)
	}
	hash, err := proto.Decrypt(secret, pinHashEnc)
	if err != nil || len(hash) != 16 {
		return nil, a.pinMismatch(left)
	}
	u, err := a.vault.Unlock(hash)
	clear(hash)
	switch {
	case errors.Is(err, vault.ErrWrongPIN):
		return nil, a.pinMismatch(left)
	case errors.Is(err, vault.ErrLockout):
		// The TPM itself refuses further guesses for a while.
		a.newKeyAgreement()
		return nil, Error(ErrPINAuthBlocked)
	case err != nil:
		return nil, Error(ErrOther)
	}
	a.consecutive = 0
	if a.events != nil {
		a.events.StateChanged()
	}
	return u, nil
}

func (a *Authenticator) pinMismatch(left int) error {
	a.newKeyAgreement()
	a.consecutive++
	if a.events != nil {
		a.events.StateChanged()
	}
	if left == 0 {
		return Error(ErrPINBlocked)
	}
	if a.consecutive >= 3 {
		a.blockedAt = time.Now()
		return Error(ErrPINAuthBlocked)
	}
	return Error(ErrPINInvalid)
}

func (a *Authenticator) newKeyAgreement() {
	if ka, err := pinuv.NewKeyAgreement(); err == nil {
		a.ka = ka
	}
}

func (a *Authenticator) changePIN(r *request, m intMap, proto pinuv.Protocol) (any, error) {
	pinHashEnc, ok1, err := m.bytes(6)
	if err != nil {
		return nil, err
	}
	newPinEnc, ok2, err := m.bytes(5)
	if err != nil {
		return nil, err
	}
	param, ok3, err := m.bytes(4)
	if err != nil {
		return nil, err
	}
	if _, ok4 := m[3]; !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, Error(ErrMissingParameter)
	}
	if !a.vault.PINSet() {
		return nil, Error(ErrPINNotSet)
	}
	if a.vault.PINRetries() == 0 {
		return nil, Error(ErrPINBlocked)
	}
	secret, err := a.sharedSecret(m, 3, proto)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	if !proto.Verify(secret, append(append([]byte(nil), newPinEnc...), pinHashEnc...), param) {
		return nil, Error(ErrPINAuthInvalid)
	}
	// Validate the new PIN before spending a retry on the old one.
	newHash, points, err := a.newPIN(proto, secret, newPinEnc)
	if err != nil {
		return nil, err
	}
	u, err := a.checkPIN(r, proto, secret, pinHashEnc, Prompt{Op: "change-pin"})
	if err != nil {
		return nil, err
	}
	u.Wipe()
	oldHash, err := proto.Decrypt(secret, pinHashEnc)
	if err != nil {
		return nil, Error(ErrPINAuthInvalid)
	}
	defer clear(oldHash)
	if err := a.vault.ChangePIN(oldHash, newHash, points); err != nil {
		return nil, Error(ErrOther)
	}
	a.stopToken()
	if a.events != nil {
		a.events.StateChanged()
		a.events.Done("change-pin", "", true)
	}
	return nil, nil
}

func (a *Authenticator) getToken(r *request, m intMap, proto pinuv.Protocol, sub uint64) (any, error) {
	pinHashEnc, ok1, err := m.bytes(6)
	if err != nil {
		return nil, err
	}
	if _, ok2 := m[3]; !ok1 || !ok2 {
		return nil, Error(ErrMissingParameter)
	}
	perms, hasPerms, err := m.uint(9)
	if err != nil {
		return nil, err
	}
	rpID, hasRPID, err := m.text(10)
	if err != nil {
		return nil, err
	}
	if sub == pinGetToken {
		if hasPerms || hasRPID {
			return nil, Error(ErrInvalidParameter)
		}
		perms = permMC | permGA
	} else {
		if !hasPerms {
			return nil, Error(ErrMissingParameter)
		}
		if perms == 0 {
			return nil, Error(ErrInvalidParameter)
		}
		// Bio enrollment, large blobs and authenticator config are not offered.
		if perms&(permBE|permLBW|permACFG) != 0 {
			return nil, Error(ErrUnauthorizedPermission)
		}
		if perms&(permMC|permGA) != 0 && !hasRPID {
			return nil, Error(ErrMissingParameter)
		}
	}
	if a.vault.PINRetries() == 0 {
		return nil, Error(ErrPINBlocked)
	}
	secret, err := a.sharedSecret(m, 3, proto)
	if err != nil {
		return nil, err
	}
	defer clear(secret)

	// What the user is confirming. Browsers ask for mc (with ga, for their
	// exclude-list probe) only to register, and for ga alone to sign in.
	op := "unlock"
	switch {
	case sub == pinGetToken:
	case perms&permMC != 0:
		op = "register"
	case perms&permGA != 0:
		op = "sign-in"
	case perms&permCM != 0:
		op = "manage"
	}
	u, err := a.checkPIN(r, proto, secret, pinHashEnc, Prompt{Op: op, RPID: rpID})
	if err != nil {
		return nil, err
	}
	// The key press collected above is the user presence for the operation
	// the token is about to authorise, so it does not need a second one.
	value, err := a.beginToken(proto, perms&(permMC|permGA|permCM), rpID, hasRPID, u, true)
	if err != nil {
		u.Wipe()
		return nil, Error(ErrOther)
	}
	enc, err := proto.Encrypt(secret, value)
	if err != nil {
		a.stopToken()
		return nil, Error(ErrOther)
	}
	return map[int]any{2: enc}, nil
}
