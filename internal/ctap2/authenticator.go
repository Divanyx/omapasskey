// Package ctap2 implements a FIDO2 (CTAP 2.1) authenticator whose keys live in
// the TPM and whose every use needs the PIN and a physical key press.
package ctap2

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/Divanyx/omapasskey/internal/ctaphid"
	"github.com/Divanyx/omapasskey/internal/pinuv"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// Commands.
const (
	cmdMakeCredential       = 0x01
	cmdGetAssertion         = 0x02
	cmdGetInfo              = 0x04
	cmdClientPIN            = 0x06
	cmdReset                = 0x07
	cmdGetNextAssertion     = 0x08
	cmdCredentialManagement = 0x0A
	cmdSelection            = 0x0B
	cmdCredMgmtPreview      = 0x41
)

// Prompt describes what the user is asked to confirm.
type Prompt struct {
	// Op is one of "register", "sign-in", "unlock", "set-pin",
	// "change-pin", "reset", "select", "exclude".
	Op   string
	RPID string
}

// Presence asks the user for a physical confirmation.
type Presence interface {
	Confirm(ctx context.Context, p Prompt) error
}

// Presence outcomes the authenticator distinguishes.
var (
	ErrPresenceTimeout = errors.New("presence timed out")
	ErrPresenceDenied  = errors.New("presence denied")
)

// Events receives notifications for the desktop.
type Events interface {
	Done(op, rpID string, ok bool)
	Wink()
	StateChanged()
}

// Config tunes the authenticator.
type Config struct {
	AAGUID       [16]byte
	MinPINLength int
	Firmware     uint64
}

// Authenticator answers CTAP2 commands.
type Authenticator struct {
	cfg      Config
	vault    *vault.Vault
	presence Presence
	events   Events

	mu           sync.Mutex
	slot         chan struct{} // admits one CTAP command at a time
	manage       sync.Mutex    // one passkey-manager request at a time
	manageQuiet  time.Time     // no manager prompts until then (after a refusal)
	cancelManage context.CancelFunc
	pmu          sync.Mutex // guards manageQuiet and cancelManage
	// presenceMu admits one key-press wait at a time, so one press can never
	// confirm two requests.
	presenceMu  sync.Mutex
	ka          *pinuv.KeyAgreement
	tok         *token
	consecutive int       // consecutive wrong PINs since the last "power cycle"
	blockedAt   time.Time // when three consecutive mismatches blocked PIN entry
	pending     *pendingAssertion
	enumRPs     *rpEnumeration
	enumCreds   *credEnumeration
}

// New builds an authenticator over an opened vault.
func New(cfg Config, v *vault.Vault, p Presence, e Events) (*Authenticator, error) {
	ka, err := pinuv.NewKeyAgreement()
	if err != nil {
		return nil, err
	}
	if cfg.MinPINLength < 4 {
		cfg.MinPINLength = 4
	}
	return &Authenticator{cfg: cfg, vault: v, presence: p, events: e, ka: ka, slot: make(chan struct{}, 1)}, nil
}

// request carries the per-command context.
type request struct {
	ctx    context.Context
	status func(byte)
}

// CBOR implements ctaphid.Handler.
func (a *Authenticator) CBOR(ctx context.Context, msg []byte, status func(byte)) []byte {
	// One command at a time; a command the platform abandoned while it was
	// queued leaves at once instead of piling up behind the lock.
	select {
	case a.slot <- struct{}{}:
	case <-ctx.Done():
		return []byte{ErrKeepaliveCancel}
	}
	defer func() { <-a.slot }()
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return []byte{ErrKeepaliveCancel}
	}
	r := &request{ctx: ctx, status: status}
	resp, err := a.dispatch(r, msg[0], msg[1:])
	if err != nil {
		var e Error
		if errors.As(err, &e) {
			return []byte{byte(e)}
		}
		return []byte{ErrOther}
	}
	if resp == nil {
		return []byte{StatusOK}
	}
	return append([]byte{StatusOK}, encode(resp)...)
}

// Wink implements ctaphid.Handler.
func (a *Authenticator) Wink() {
	if a.events != nil {
		a.events.Wink()
	}
}

func (a *Authenticator) dispatch(r *request, cmd byte, params []byte) (any, error) {
	// Stateful continuations are only valid immediately after their command.
	if cmd != cmdGetNextAssertion {
		a.dropPending()
	}
	if cmd != cmdCredentialManagement && cmd != cmdCredMgmtPreview {
		a.enumRPs, a.enumCreds = nil, nil
	}
	switch cmd {
	case cmdGetInfo:
		if len(params) != 0 {
			return nil, Error(ErrInvalidLength)
		}
		return a.getInfo(), nil
	case cmdMakeCredential:
		return a.makeCredential(r, params)
	case cmdGetAssertion:
		return a.getAssertion(r, params)
	case cmdGetNextAssertion:
		return a.getNextAssertion()
	case cmdClientPIN:
		return a.clientPIN(r, params)
	case cmdReset:
		return a.reset(r)
	case cmdCredentialManagement, cmdCredMgmtPreview:
		return a.credentialManagement(r, params)
	case cmdSelection:
		if err := a.confirm(r, Prompt{Op: "select"}, true); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return nil, Error(ErrInvalidCommand)
}

func (a *Authenticator) getInfo() map[int]any {
	disc, _ := a.vault.Counts()
	pinSet := a.vault.PINSet()
	return map[int]any{
		1: []string{"FIDO_2_0", "FIDO_2_1"},
		2: []string{"credProtect", "hmac-secret"},
		3: a.cfg.AAGUID[:],
		4: map[string]bool{
			"rk":               true,
			"up":               true,
			"plat":             false,
			"clientPin":        pinSet,
			"pinUvAuthToken":   true,
			"credMgmt":         true,
			"alwaysUv":         true,
			"makeCredUvNotRqd": false,
		},
		5:  ctaphid.MaxMessage,
		6:  []uint64{2, 1},
		7:  32,  // maxCredentialCountInList
		8:  128, // maxCredentialIdLength
		9:  []string{"usb"},
		10: []map[string]any{{"alg": -7, "type": "public-key"}},
		13: a.cfg.MinPINLength,
		14: a.cfg.Firmware,
		20: vault.MaxDiscoverable - disc,
	}
}

// confirm collects the physical gesture. The host sees "user presence
// needed" keepalives meanwhile. selection reports a timeout as such, all
// other commands as "operation denied", per the spec.
func (a *Authenticator) confirm(r *request, p Prompt, selection bool) error {
	r.status(ctaphid.StatusUPNeeded)
	defer r.status(ctaphid.StatusProcessing)
	// A browser request outranks the passkey manager: a manager prompt that
	// is still open is withdrawn rather than letting it delay a sign-in.
	if p.Op != "manage" {
		a.pmu.Lock()
		if a.cancelManage != nil {
			a.cancelManage()
		}
		a.pmu.Unlock()
		a.presenceMu.Lock()
	} else if !a.presenceMu.TryLock() {
		return ErrPresenceDenied
	}
	err := a.presence.Confirm(r.ctx, p)
	a.presenceMu.Unlock()
	switch {
	case err == nil:
		return nil
	case r.ctx.Err() != nil:
		return Error(ErrKeepaliveCancel)
	case errors.Is(err, ErrPresenceTimeout) && selection:
		return Error(ErrUserActionTimeout)
	}
	return Error(ErrOperationDenied)
}

func (a *Authenticator) reset(r *request) (any, error) {
	if err := a.confirm(r, Prompt{Op: "reset"}, false); err != nil {
		return nil, err
	}
	if err := a.vault.Reset(); err != nil {
		return nil, Error(ErrOther)
	}
	a.stopToken()
	a.consecutive = 0
	a.blockedAt = time.Time{}
	if ka, err := pinuv.NewKeyAgreement(); err == nil {
		a.ka = ka
	}
	if a.events != nil {
		a.events.StateChanged()
		a.events.Done("reset", "", true)
	}
	return nil, nil
}

// PowerCycle forgets volatile state as unplugging a key would.
func (a *Authenticator) PowerCycle() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopToken()
	a.dropPending()
	a.enumRPs, a.enumCreds = nil, nil
	a.consecutive = 0
	a.blockedAt = time.Time{}
	if ka, err := pinuv.NewKeyAgreement(); err == nil {
		a.ka = ka
	}
}

func rpHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}
