// Package vault keeps the authenticator's state: the PIN-sealed master secret,
// and one record per credential whose private key lives in the TPM.
//
// Key hierarchy:
//
//	PIN ──HKDF(salt)──► TPM auth value of a sealed, dictionary-attack-protected
//	                    object that holds the 32-byte master secret G
//	G ──HKDF──► auth value of every credential key in the TPM
//	G ──HKDF──► AES-256-GCM key for the credential metadata (site, account)
//
// Without the PIN the TPM releases nothing, the credential keys cannot sign,
// and the metadata cannot be read — not even by root, short of guessing the
// PIN against the TPM's lockout.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Divanyx/omapasskey/internal/tpm"
)

// MaxPINRetries is the CTAP maximum.
const MaxPINRetries = 8

const (
	stateVersion = 1
	// Generous limits; they only bound a file that grows with the user's own
	// confirmed registrations.
	MaxDiscoverable = 1000
	maxCredentials  = 5000
)

var (
	ErrPINNotSet  = errors.New("vault: no PIN set")
	ErrPINSet     = errors.New("vault: a PIN is already set")
	ErrWrongPIN   = errors.New("vault: wrong PIN")
	ErrLockout    = errors.New("vault: TPM lockout")
	ErrFull       = errors.New("vault: credential store full")
	ErrNotFound   = errors.New("vault: no such credential")
	ErrCorrupt    = errors.New("vault: credential metadata failed authentication")
	errBadSecret  = errors.New("vault: bad master secret")
	errNilUnlock  = errors.New("vault: locked")
	errBadPINHash = errors.New("vault: PIN hash must be 16 bytes")
)

// Backend is the subset of the TPM the vault needs.
type Backend interface {
	Seal(secret, auth []byte) (tpm.Blob, error)
	Unseal(b tpm.Blob, auth []byte) ([]byte, error)
	CreateSigningKey(auth []byte) (tpm.Blob, []byte, []byte, error)
	Sign(b tpm.Blob, auth, digest []byte) ([]byte, []byte, error)
	CreateHMACKey(auth []byte) (tpm.Blob, error)
	HMAC(b tpm.Blob, auth, data []byte) ([]byte, error)
	Random(n int) ([]byte, error)
}

// Credential is one stored credential. Everything that identifies the site or
// the account is in Sealed; the rest is needed to find a credential before
// the PIN is known and reveals nothing beyond the RP ID hash.
type Credential struct {
	ID           []byte    `json:"id"`
	RPIDHash     []byte    `json:"rpIdHash"`
	Discoverable bool      `json:"discoverable"`
	CredProtect  int       `json:"credProtect"`
	Created      int64     `json:"created"`
	Key          tpm.Blob  `json:"key"`
	HMACKey      *tpm.Blob `json:"hmacKey,omitempty"`
	PublicX      []byte    `json:"publicX"`
	PublicY      []byte    `json:"publicY"`
	Sealed       []byte    `json:"sealed"`
}

// Account is the sealed part of a credential.
type Account struct {
	RPID        string `json:"rpId"`
	RPName      string `json:"rpName,omitempty"`
	UserID      []byte `json:"userId"`
	UserName    string `json:"userName,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type pinState struct {
	Salt       []byte   `json:"salt"`
	Sealed     tpm.Blob `json:"sealed"`
	Retries    int      `json:"retries"`
	CodePoints int      `json:"codePoints"`
	Changed    int64    `json:"changed"`
}

type state struct {
	Version     int           `json:"version"`
	PIN         *pinState     `json:"pin,omitempty"`
	Credentials []*Credential `json:"credentials"`
}

// Vault is the persistent store. All methods are safe for concurrent use.
type Vault struct {
	mu   sync.Mutex
	path string
	be   Backend
	st   state
}

// Unlocked holds the master secret for the duration of one ceremony.
type Unlocked struct {
	keyAuth []byte
	metaKey []byte
}

// Clone returns an independent copy, so that a token can be wiped while an
// operation it authorised is still running.
func (u *Unlocked) Clone() *Unlocked {
	if u == nil {
		return nil
	}
	return &Unlocked{keyAuth: append([]byte(nil), u.keyAuth...), metaKey: append([]byte(nil), u.metaKey...)}
}

// Wipe overwrites the secrets.
func (u *Unlocked) Wipe() {
	if u == nil {
		return
	}
	clear(u.keyAuth)
	clear(u.metaKey)
}

func derive(g []byte) (*Unlocked, error) {
	if len(g) != 32 {
		return nil, errBadSecret
	}
	material, err := hkdf.Key(sha256.New, g, nil, "omapasskey/v1/key-auth", 24)
	if err != nil {
		return nil, err
	}
	keyAuth := tpm.AuthValue(material)
	clear(material)
	metaKey, err := hkdf.Key(sha256.New, g, nil, "omapasskey/v1/metadata", 32)
	if err != nil {
		return nil, err
	}
	return &Unlocked{keyAuth: keyAuth, metaKey: metaKey}, nil
}

func pinAuth(pinHash, salt []byte) ([]byte, error) {
	if len(pinHash) != 16 {
		return nil, errBadPINHash
	}
	material, err := hkdf.Key(sha256.New, pinHash, salt, "omapasskey/v1/pin-auth", 24)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	return tpm.AuthValue(material), nil
}

// Open loads the state at path, or starts empty if there is none.
func Open(path string, be Backend) (*Vault, error) {
	v := &Vault{path: path, be: be, st: state{Version: stateVersion}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &v.st); err != nil {
		return nil, fmt.Errorf("vault: %s is damaged: %w", path, err)
	}
	if v.st.Version != stateVersion {
		return nil, fmt.Errorf("vault: unsupported state version %d", v.st.Version)
	}
	return v, nil
}

// save writes the state atomically: temp file, fsync, rename, fsync dir.
func (v *Vault) save() error {
	data, err := json.MarshalIndent(&v.st, "", " ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(v.path)
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), v.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func (v *Vault) random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	// Mix in the TPM's generator: either source alone would be enough.
	t, err := v.be.Random(n)
	if err != nil {
		return nil, err
	}
	for i := range b {
		b[i] ^= t[i]
	}
	return b, nil
}

// PINSet reports whether a PIN protects the vault.
func (v *Vault) PINSet() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.st.PIN != nil
}

// PINRetries returns the remaining PIN attempts.
func (v *Vault) PINRetries() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.st.PIN == nil {
		return MaxPINRetries
	}
	return v.st.PIN.Retries
}

// SetPIN protects a fresh vault with a PIN, given as LEFT(SHA-256(PIN), 16).
func (v *Vault) SetPIN(pinHash []byte, codePoints int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.st.PIN != nil {
		return ErrPINSet
	}
	g, err := v.random(32)
	if err != nil {
		return err
	}
	defer clear(g)
	ps, err := v.sealSecret(g, pinHash, codePoints)
	if err != nil {
		return err
	}
	v.st.PIN = ps
	return v.save()
}

func (v *Vault) sealSecret(g, pinHash []byte, codePoints int) (*pinState, error) {
	salt, err := v.random(32)
	if err != nil {
		return nil, err
	}
	auth, err := pinAuth(pinHash, salt)
	if err != nil {
		return nil, err
	}
	defer clear(auth)
	blob, err := v.be.Seal(g, auth)
	if err != nil {
		return nil, err
	}
	return &pinState{
		Salt: salt, Sealed: blob, Retries: MaxPINRetries,
		CodePoints: codePoints, Changed: time.Now().Unix(),
	}, nil
}

// ConsumePINRetry decrements the retry counter before a PIN is checked, as
// CTAP requires, and persists it. It returns the remaining count.
func (v *Vault) ConsumePINRetry() (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.st.PIN == nil {
		return 0, ErrPINNotSet
	}
	if v.st.PIN.Retries > 0 {
		v.st.PIN.Retries--
	}
	return v.st.PIN.Retries, v.save()
}

// Unlock checks a PIN hash against the TPM and returns the unlocked secrets.
// On success the retry counter is restored; a wrong PIN returns ErrWrongPIN
// and has already counted against the TPM's lockout.
func (v *Vault) Unlock(pinHash []byte) (*Unlocked, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.st.PIN == nil {
		return nil, ErrPINNotSet
	}
	g, err := v.unseal(pinHash)
	if err != nil {
		return nil, err
	}
	defer clear(g)
	u, err := derive(g)
	if err != nil {
		return nil, err
	}
	v.st.PIN.Retries = MaxPINRetries
	if err := v.save(); err != nil {
		u.Wipe()
		return nil, err
	}
	return u, nil
}

func (v *Vault) unseal(pinHash []byte) ([]byte, error) {
	auth, err := pinAuth(pinHash, v.st.PIN.Salt)
	if err != nil {
		return nil, err
	}
	defer clear(auth)
	g, err := v.be.Unseal(v.st.PIN.Sealed, auth)
	switch {
	case errors.Is(err, tpm.ErrBadAuth):
		return nil, ErrWrongPIN
	case errors.Is(err, tpm.ErrLockout):
		return nil, ErrLockout
	case err != nil:
		return nil, err
	}
	return g, nil
}

// ChangePIN re-seals the master secret under a new PIN. The old PIN must be
// correct; credentials are unaffected.
func (v *Vault) ChangePIN(oldHash, newHash []byte, codePoints int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.st.PIN == nil {
		return ErrPINNotSet
	}
	g, err := v.unseal(oldHash)
	if err != nil {
		return err
	}
	defer clear(g)
	ps, err := v.sealSecret(g, newHash, codePoints)
	if err != nil {
		return err
	}
	v.st.PIN = ps
	return v.save()
}

// Reset forgets the PIN and every credential.
func (v *Vault) Reset() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.st = state{Version: stateVersion}
	return v.save()
}

// Counts returns the number of discoverable and of all credentials.
func (v *Vault) Counts() (discoverable, total int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.st.Credentials {
		if c.Discoverable {
			discoverable++
		}
	}
	return discoverable, len(v.st.Credentials)
}

// Find returns the credential with this ID if it belongs to the RP.
func (v *Vault) Find(id, rpIDHash []byte) *Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.st.Credentials {
		if bytes.Equal(c.ID, id) && bytes.Equal(c.RPIDHash, rpIDHash) {
			return c
		}
	}
	return nil
}

// FindByID returns the credential with this ID for any RP.
func (v *Vault) FindByID(id []byte) *Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.st.Credentials {
		if bytes.Equal(c.ID, id) {
			return c
		}
	}
	return nil
}

// Discoverable returns the RP's discoverable credentials, newest first.
// A nil rpIDHash returns all of them.
func (v *Vault) Discoverable(rpIDHash []byte) []*Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []*Credential
	for _, c := range v.st.Credentials {
		if c.Discoverable && (rpIDHash == nil || bytes.Equal(c.RPIDHash, rpIDHash)) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out
}

// All returns every credential, newest first.
func (v *Vault) All() []*Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := append([]*Credential(nil), v.st.Credentials...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out
}

// Account decrypts a credential's sealed metadata.
func (v *Vault) Account(u *Unlocked, c *Credential) (*Account, error) {
	if u == nil {
		return nil, errNilUnlock
	}
	plain, err := open(u.metaKey, c.ID, c.Sealed)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var a Account
	if err := json.Unmarshal(plain, &a); err != nil {
		return nil, ErrCorrupt
	}
	return &a, nil
}

// NewCredential creates a credential: its signing key (and optionally an
// HMAC key for hmac-secret) in the TPM, its sealed metadata, and stores it.
// A discoverable credential replaces an existing one for the same account.
func (v *Vault) NewCredential(u *Unlocked, a *Account, discoverable bool, credProtect int, withHMAC bool) (*Credential, error) {
	if u == nil {
		return nil, errNilUnlock
	}
	v.mu.Lock()
	n := len(v.st.Credentials)
	disc := 0
	for _, c := range v.st.Credentials {
		if c.Discoverable {
			disc++
		}
	}
	v.mu.Unlock()
	if n >= maxCredentials || (discoverable && disc >= MaxDiscoverable) {
		return nil, ErrFull
	}

	keyBlob, x, y, err := v.be.CreateSigningKey(u.keyAuth)
	if err != nil {
		return nil, err
	}
	var hmacBlob *tpm.Blob
	if withHMAC {
		b, err := v.be.CreateHMACKey(u.keyAuth)
		if err != nil {
			return nil, err
		}
		hmacBlob = &b
	}
	id, err := v.random(32)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	sealed, err := seal(u.metaKey, id, plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	rpHash := sha256.Sum256([]byte(a.RPID))
	c := &Credential{
		ID: id, RPIDHash: rpHash[:], Discoverable: discoverable, CredProtect: credProtect,
		Created: time.Now().UnixNano(), Key: keyBlob, HMACKey: hmacBlob,
		PublicX: x, PublicY: y, Sealed: sealed,
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if discoverable {
		kept := v.st.Credentials[:0]
		for _, old := range v.st.Credentials {
			if old.Discoverable && bytes.Equal(old.RPIDHash, c.RPIDHash) {
				if oa, err := v.accountLocked(u, old); err == nil && bytes.Equal(oa.UserID, a.UserID) {
					continue // overwritten by the new credential
				}
			}
			kept = append(kept, old)
		}
		v.st.Credentials = kept
	}
	v.st.Credentials = append(v.st.Credentials, c)
	if err := v.save(); err != nil {
		return nil, err
	}
	return c, nil
}

func (v *Vault) accountLocked(u *Unlocked, c *Credential) (*Account, error) {
	plain, err := open(u.metaKey, c.ID, c.Sealed)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var a Account
	if err := json.Unmarshal(plain, &a); err != nil {
		return nil, ErrCorrupt
	}
	return &a, nil
}

// UpdateAccount replaces a credential's user name and display name.
func (v *Vault) UpdateAccount(u *Unlocked, id []byte, name, displayName string) error {
	if u == nil {
		return errNilUnlock
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.st.Credentials {
		if !bytes.Equal(c.ID, id) {
			continue
		}
		a, err := v.accountLocked(u, c)
		if err != nil {
			return err
		}
		a.UserName, a.DisplayName = name, displayName
		plain, err := json.Marshal(a)
		if err != nil {
			return err
		}
		sealed, err := seal(u.metaKey, c.ID, plain)
		clear(plain)
		if err != nil {
			return err
		}
		c.Sealed = sealed
		return v.save()
	}
	return ErrNotFound
}

// Delete removes a credential.
func (v *Vault) Delete(id []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i, c := range v.st.Credentials {
		if bytes.Equal(c.ID, id) {
			v.st.Credentials = append(v.st.Credentials[:i], v.st.Credentials[i+1:]...)
			return v.save()
		}
	}
	return ErrNotFound
}

// Sign signs a SHA-256 digest with the credential's TPM key.
func (v *Vault) Sign(u *Unlocked, c *Credential, digest []byte) (r, s []byte, err error) {
	if u == nil {
		return nil, nil, errNilUnlock
	}
	return v.be.Sign(c.Key, u.keyAuth, digest)
}

// HMAC computes the credential's hmac-secret output for data.
func (v *Vault) HMAC(u *Unlocked, c *Credential, data []byte) ([]byte, error) {
	if u == nil {
		return nil, errNilUnlock
	}
	if c.HMACKey == nil {
		return nil, ErrNotFound
	}
	return v.be.HMAC(*c.HMACKey, u.keyAuth, data)
}

// seal encrypts metadata with AES-256-GCM, bound to the credential ID.
func seal(key, id, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, id), nil
}

func open(key, id, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, ErrCorrupt
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], id)
	if err != nil {
		return nil, ErrCorrupt
	}
	return plain, nil
}
