package ctap2

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/Divanyx/omapasskey/internal/vault"
)

// Errors of the local administration interface (root only).
var (
	ErrAdminPINSet    = errors.New("a PIN is already set")
	ErrAdminNoPIN     = errors.New("no PIN is set")
	ErrAdminPolicy    = errors.New("the PIN does not meet the policy")
	ErrAdminWrongPIN  = errors.New("wrong PIN")
	ErrAdminBlocked   = errors.New("the PIN is blocked; only a reset helps now")
	ErrAdminLockout   = errors.New("too many wrong PINs; wait and try again")
	ErrAdminNotFound  = errors.New("no such passkey")
	ErrAdminInternal  = errors.New("internal error")
	errAdminAmbiguous = errors.New("ambiguous passkey id")
)

// AccountInfo describes one stored passkey.
type AccountInfo struct {
	ID           []byte `json:"id"`
	RPID         string `json:"rpId"`
	RPName       string `json:"rpName,omitempty"`
	UserName     string `json:"userName,omitempty"`
	DisplayName  string `json:"displayName,omitempty"`
	Discoverable bool   `json:"discoverable"`
	CredProtect  int    `json:"credProtect"`
	Created      int64  `json:"created"`
	PRF          bool   `json:"prf"`
}

// Status is a summary for the administration tools.
type Status struct {
	PINSet       bool `json:"pinSet"`
	PINRetries   int  `json:"pinRetries"`
	Discoverable int  `json:"discoverable"`
	Total        int  `json:"total"`
	MinPINLength int  `json:"minPinLength"`
}

// AdminStatus reports the PIN and credential counts. It reads only the
// vault, which locks itself, so it never waits for a command that is
// waiting for the user — and can be called from event handlers.
func (a *Authenticator) AdminStatus() Status {
	disc, total := a.vault.Counts()
	return Status{
		PINSet: a.vault.PINSet(), PINRetries: a.vault.PINRetries(),
		Discoverable: disc, Total: total, MinPINLength: a.cfg.MinPINLength,
	}
}

func (a *Authenticator) pinHash(pin string) ([]byte, int, error) {
	if !utf8.ValidString(pin) || len(pin) > 63 {
		return nil, 0, ErrAdminPolicy
	}
	n := utf8.RuneCountInString(pin)
	if n < a.cfg.MinPINLength {
		return nil, 0, ErrAdminPolicy
	}
	h := sha256.Sum256([]byte(pin))
	return h[:16], n, nil
}

// AdminSetPIN sets the first PIN.
func (a *Authenticator) AdminSetPIN(pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.vault.PINSet() {
		return ErrAdminPINSet
	}
	h, n, err := a.pinHash(pin)
	if err != nil {
		return err
	}
	if err := a.vault.SetPIN(h, n); err != nil {
		return ErrAdminInternal
	}
	if a.events != nil {
		a.events.StateChanged()
	}
	return nil
}

// adminUnlock checks a PIN with the same retry accounting as CTAP.
func (a *Authenticator) adminUnlock(pin string) (*vault.Unlocked, error) {
	if !a.vault.PINSet() {
		return nil, ErrAdminNoPIN
	}
	if a.vault.PINRetries() == 0 {
		return nil, ErrAdminBlocked
	}
	if a.authBlocked() {
		return nil, ErrAdminLockout
	}
	if _, err := a.vault.ConsumePINRetry(); err != nil {
		return nil, ErrAdminInternal
	}
	h := sha256.Sum256([]byte(pin))
	u, err := a.vault.Unlock(h[:16])
	switch {
	case errors.Is(err, vault.ErrWrongPIN):
		a.consecutive++
		if a.consecutive >= 3 {
			a.blockedAt = time.Now()
		}
		if a.events != nil {
			a.events.StateChanged()
		}
		if a.vault.PINRetries() == 0 {
			return nil, ErrAdminBlocked
		}
		return nil, ErrAdminWrongPIN
	case errors.Is(err, vault.ErrLockout):
		return nil, ErrAdminLockout
	case err != nil:
		return nil, ErrAdminInternal
	}
	a.consecutive = 0
	if a.events != nil {
		a.events.StateChanged()
	}
	return u, nil
}

// AdminChangePIN replaces the PIN.
func (a *Authenticator) AdminChangePIN(oldPIN, newPIN string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	newHash, n, err := a.pinHash(newPIN)
	if err != nil {
		return err
	}
	u, err := a.adminUnlock(oldPIN)
	if err != nil {
		return err
	}
	u.Wipe()
	oldHash := sha256.Sum256([]byte(oldPIN))
	if err := a.vault.ChangePIN(oldHash[:16], newHash, n); err != nil {
		return ErrAdminInternal
	}
	a.stopToken()
	return nil
}

// AdminList returns every stored passkey.
func (a *Authenticator) AdminList(pin string) ([]AccountInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, err := a.adminUnlock(pin)
	if err != nil {
		return nil, err
	}
	defer u.Wipe()
	return a.accounts(u)
}

func (a *Authenticator) accounts(u *vault.Unlocked) ([]AccountInfo, error) {
	var out []AccountInfo
	for _, c := range a.vault.All() {
		acct, err := a.vault.Account(u, c)
		if err != nil {
			return nil, ErrAdminInternal
		}
		out = append(out, AccountInfo{
			ID: c.ID, RPID: acct.RPID, RPName: acct.RPName,
			UserName: acct.UserName, DisplayName: acct.DisplayName,
			Discoverable: c.Discoverable, CredProtect: c.CredProtect,
			Created: c.Created / int64(time.Second), PRF: c.HMACKey != nil,
		})
	}
	return out, nil
}

// AdminDelete removes the passkey whose ID starts with prefix.
func (a *Authenticator) AdminDelete(pin string, prefix []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, err := a.adminUnlock(pin)
	if err != nil {
		return err
	}
	defer u.Wipe()
	var match *vault.Credential
	for _, c := range a.vault.All() {
		if len(prefix) > 0 && len(c.ID) >= len(prefix) && string(c.ID[:len(prefix)]) == string(prefix) {
			if match != nil {
				return errAdminAmbiguous
			}
			match = c
		}
	}
	if match == nil {
		return ErrAdminNotFound
	}
	if err := a.vault.Delete(match.ID); err != nil {
		return ErrAdminInternal
	}
	if a.events != nil {
		a.events.Done("delete", "", true)
	}
	return nil
}

// AdminReset forgets the PIN and every passkey.
func (a *Authenticator) AdminReset() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.vault.Reset(); err != nil {
		return ErrAdminInternal
	}
	a.stopToken()
	a.dropPending()
	a.consecutive = 0
	a.blockedAt = time.Time{}
	a.newKeyAgreement()
	if a.events != nil {
		a.events.StateChanged()
		a.events.Done("reset", "", true)
	}
	return nil
}

// userUnlock is adminUnlock for an ordinary user: it first asks for the
// physical confirmation, so neither the passkey list nor a PIN try can be had
// by software alone.
func (a *Authenticator) userUnlock(ctx context.Context, pin string) (*vault.Unlocked, error) {
	if !a.vault.PINSet() {
		return nil, ErrAdminNoPIN
	}
	if a.vault.PINRetries() == 0 {
		return nil, ErrAdminBlocked
	}
	if a.authBlocked() {
		return nil, ErrAdminLockout
	}
	r := &request{ctx: ctx, status: func(byte) {}}
	if err := a.confirm(r, Prompt{Op: "manage"}, false); err != nil {
		return nil, ErrNotConfirmed
	}
	return a.adminUnlock(pin)
}

// ErrNotConfirmed means the key combination was not pressed.
var ErrNotConfirmed = errors.New("not confirmed on the keyboard")

// UserList lists the passkeys after the PIN and a key press.
func (a *Authenticator) UserList(ctx context.Context, pin string) ([]AccountInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, err := a.userUnlock(ctx, pin)
	if err != nil {
		return nil, err
	}
	defer u.Wipe()
	return a.accounts(u)
}

// UserDelete deletes one passkey after the PIN and a key press and returns
// the remaining list.
func (a *Authenticator) UserDelete(ctx context.Context, pin string, id []byte) ([]AccountInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, err := a.userUnlock(ctx, pin)
	if err != nil {
		return nil, err
	}
	defer u.Wipe()
	if a.vault.FindByID(id) == nil {
		return nil, ErrAdminNotFound
	}
	if err := a.vault.Delete(id); err != nil {
		return nil, ErrAdminInternal
	}
	if a.events != nil {
		a.events.Done("delete", "", true)
	}
	return a.accounts(u)
}
