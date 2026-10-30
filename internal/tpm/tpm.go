// Package tpm keeps every private key of Omapasskey inside the TPM. Keys are
// created by the TPM, marked fixedTPM|fixedParent so they can never be
// exported, and stored on disk only as TPM-wrapped blobs that are useless
// on any other machine.
package tpm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

var (
	// ErrBadAuth means the authorization value (the PIN) was wrong.
	ErrBadAuth = errors.New("tpm: authorization failed")
	// ErrLockout means the TPM's dictionary-attack protection is engaged.
	ErrLockout = errors.New("tpm: dictionary-attack lockout")
)

// AuthValue turns 24 bytes (192 bits) of key material into a 32-byte TPM
// authorization value without zero bytes. The TPM drops trailing zeros of an
// auth value when it computes session HMACs, and go-tpm v0.9.8 drops
// everything from the first zero on, so a value with a zero byte in it can
// fail to authorize. Base64url never produces one.
func AuthValue(material []byte) []byte {
	if len(material) != 24 {
		panic("tpm: AuthValue needs exactly 24 bytes of key material")
	}
	return []byte(base64.RawURLEncoding.EncodeToString(material))
}

var errZeroAuth = errors.New("tpm: auth values must not contain zero bytes (use AuthValue)")

func checkAuth(auth []byte) error {
	if bytes.IndexByte(auth, 0) >= 0 {
		return errZeroAuth
	}
	return nil
}

// Blob is a TPM-wrapped object: its public area and its private area, which
// only this TPM can decrypt.
type Blob struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

// TPM is a connection with a loaded storage root key.
type TPM struct {
	mu     sync.Mutex
	t      transport.TPMCloser
	srk    tpm2.TPMHandle
	srkNm  tpm2.TPM2BName
	srkPub tpm2.TPMTPublic
}

// Open connects to the kernel resource manager at path (usually /dev/tpmrm0).
func Open(path string) (*TPM, error) {
	t, err := linuxtpm.Open(path)
	if err != nil {
		return nil, err
	}
	return New(t)
}

// New uses an established transport (the simulator in tests).
func New(t transport.TPMCloser) (*TPM, error) {
	// The TCG reference ECC SRK: deterministic from the owner seed, so the same
	// key comes back on every start without being persisted in NV memory.
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		t.Close()
		if errors.Is(err, tpm2.TPMRCBadAuth) || errors.Is(err, tpm2.TPMRCAuthFail) {
			return nil, fmt.Errorf("tpm: the owner hierarchy has a password; Omapasskey needs the standard empty owner authorization: %w", err)
		}
		return nil, fmt.Errorf("tpm: creating the storage root key: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Close()
		return nil, err
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		t.Close()
		return nil, err
	}
	return &TPM{t: t, srk: rsp.ObjectHandle, srkNm: *name, srkPub: *pub}, nil
}

// Close flushes the storage root key and closes the connection.
func (k *TPM) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	tpm2.FlushContext{FlushHandle: k.srk}.Execute(k.t)
	return k.t.Close()
}

// session returns a salted HMAC session (salted to the SRK, so the auth value
// never crosses the bus in the clear) with optional parameter encryption.
func (k *TPM) session(auth []byte, enc ...tpm2.AuthOption) tpm2.Session {
	opts := []tpm2.AuthOption{tpm2.Auth(auth), tpm2.Salted(k.srk, k.srkPub)}
	opts = append(opts, enc...)
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...)
}

func (k *TPM) parent(enc ...tpm2.AuthOption) tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: k.srk, Name: k.srkNm, Auth: k.session(nil, enc...)}
}

func (k *TPM) create(pub tpm2.TPMTPublic, auth, data []byte) (Blob, *tpm2.TPMTPublic, error) {
	sens := tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth}}
	if data != nil {
		sens.Data = tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data})
	}
	rsp, err := tpm2.Create{
		// Parameter encryption keeps the new auth value and sealed data off the bus.
		ParentHandle: k.parent(tpm2.AESEncryption(128, tpm2.EncryptIn)),
		InSensitive:  tpm2.TPM2BSensitiveCreate{Sensitive: &sens},
		InPublic:     tpm2.New2B(pub),
	}.Execute(k.t)
	if err != nil {
		return Blob{}, nil, err
	}
	out, err := rsp.OutPublic.Contents()
	if err != nil {
		return Blob{}, nil, err
	}
	return Blob{Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate)}, out, nil
}

// load loads a blob under the SRK and returns its handle and name.
func (k *TPM) load(b Blob) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("tpm: bad public blob: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("tpm: bad private blob: %w", err)
	}
	rsp, err := tpm2.Load{ParentHandle: k.parent(), InPrivate: *priv, InPublic: *pub}.Execute(k.t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, err
	}
	return rsp.ObjectHandle, rsp.Name, nil
}

func (k *TPM) flush(h tpm2.TPMHandle) {
	tpm2.FlushContext{FlushHandle: h}.Execute(k.t)
}

func mapAuthError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, tpm2.TPMRCLockout):
		return ErrLockout
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return ErrBadAuth
	}
	return err
}

// Seal stores secret in a sealed data object that only releases it to the
// given auth value. The object is subject to the TPM's dictionary-attack
// protection: wrong guesses count towards the TPM-wide lockout.
func (k *TPM) Seal(secret, auth []byte) (Blob, error) {
	if err := checkAuth(auth); err != nil {
		return Blob{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	b, _, err := k.create(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         false,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
		}),
	}, auth, secret)
	return b, err
}

// Unseal releases a sealed secret. A wrong auth value returns ErrBadAuth and
// counts against the TPM's lockout; an engaged lockout returns ErrLockout.
func (k *TPM) Unseal(b Blob, auth []byte) ([]byte, error) {
	if err := checkAuth(auth); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	h, name, err := k.load(b)
	if err != nil {
		return nil, err
	}
	defer k.flush(h)
	rsp, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: h, Name: name,
		// Response encryption: the secret leaves the TPM encrypted.
		Auth: k.session(auth, tpm2.AESEncryption(128, tpm2.EncryptOut)),
	}}.Execute(k.t)
	if err != nil {
		return nil, mapAuthError(err)
	}
	return rsp.OutData.Buffer, nil
}

// CreateSigningKey creates a P-256 ECDSA key that never leaves the TPM and
// returns its blob and its public point.
func (k *TPM) CreateSigningKey(auth []byte) (b Blob, x, y []byte, err error) {
	if err := checkAuth(auth); err != nil {
		return Blob{}, nil, nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	b, pub, err := k.create(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			// The auth value is a random 256-bit key, not something a person
			// chose, so guessing it is hopeless without the lockout.
			NoDA:        true,
			SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}, auth, nil)
	if err != nil {
		return Blob{}, nil, nil, err
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return Blob{}, nil, nil, err
	}
	return b, pad32(point.X.Buffer), pad32(point.Y.Buffer), nil
}

// Sign signs a SHA-256 digest with a signing key and returns r and s.
func (k *TPM) Sign(b Blob, auth, digest []byte) (r, s []byte, err error) {
	if len(digest) != 32 {
		return nil, nil, errors.New("tpm: digest must be 32 bytes")
	}
	if err := checkAuth(auth); err != nil {
		return nil, nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	h, name, err := k.load(b)
	if err != nil {
		return nil, nil, err
	}
	defer k.flush(h)
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: h, Name: name, Auth: k.session(auth)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(k.t)
	if err != nil {
		return nil, nil, mapAuthError(err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, nil, err
	}
	return sig.SignatureR.Buffer, sig.SignatureS.Buffer, nil
}

// CreateHMACKey creates an HMAC-SHA-256 key generated by and kept in the TPM;
// it backs the hmac-secret (PRF) extension.
func (k *TPM) CreateHMACKey(auth []byte) (Blob, error) {
	if err := checkAuth(auth); err != nil {
		return Blob{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	b, _, err := k.create(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme:  tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}),
	}, auth, nil)
	return b, err
}

// HMAC computes HMAC-SHA-256 over data with an HMAC key.
func (k *TPM) HMAC(b Blob, auth, data []byte) ([]byte, error) {
	if err := checkAuth(auth); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	h, name, err := k.load(b)
	if err != nil {
		return nil, err
	}
	defer k.flush(h)
	rsp, err := tpm2.Hmac{
		Handle: tpm2.AuthHandle{
			Handle: h, Name: name,
			Auth: k.session(auth, tpm2.AESEncryption(128, tpm2.EncryptInOut)),
		},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: data},
		HashAlg: tpm2.TPMAlgSHA256,
	}.Execute(k.t)
	if err != nil {
		return nil, mapAuthError(err)
	}
	return rsp.OutHMAC.Buffer, nil
}

// Random returns n bytes from the TPM's random number generator.
func (k *TPM) Random(n int) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]byte, 0, n)
	for len(out) < n {
		want := n - len(out)
		if want > 32 {
			want = 32
		}
		rsp, err := tpm2.GetRandom{BytesRequested: uint16(want)}.Execute(k.t)
		if err != nil {
			return nil, err
		}
		out = append(out, rsp.RandomBytes.Buffer...)
	}
	return out, nil
}

// Info describes the TPM and its dictionary-attack settings.
type Info struct {
	Manufacturer    string `json:"manufacturer"`
	LockoutCounter  uint32 `json:"lockoutCounter"`
	MaxAuthFail     uint32 `json:"maxAuthFail"`
	LockoutInterval uint32 `json:"lockoutInterval"`
	LockoutRecovery uint32 `json:"lockoutRecovery"`
	InLockout       bool   `json:"inLockout"`
	LockoutAuthSet  bool   `json:"lockoutAuthSet"`
	OwnerAuthSet    bool   `json:"ownerAuthSet"`
}

// Info reads the TPM's properties.
func (k *TPM) Info() (Info, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var info Info
	props := map[tpm2.TPMPT]uint32{}
	for _, start := range []tpm2.TPMPT{tpm2.TPMPTManufacturer, tpm2.TPMPTPermanent} {
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(start),
			PropertyCount: 32,
		}.Execute(k.t)
		if err != nil {
			return info, err
		}
		list, err := rsp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return info, err
		}
		for _, p := range list.TPMProperty {
			props[p.Property] = p.Value
		}
	}
	m := props[tpm2.TPMPTManufacturer]
	info.Manufacturer = string([]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)})
	info.LockoutCounter = props[tpm2.TPMPTLockoutCounter]
	info.MaxAuthFail = props[tpm2.TPMPTMaxAuthFail]
	info.LockoutInterval = props[tpm2.TPMPTLockoutInterval]
	info.LockoutRecovery = props[tpm2.TPMPTLockoutRecovery]
	perm := props[tpm2.TPMPTPermanent]
	// TPMA_PERMANENT: ownerAuthSet bit 0, endorsementAuthSet bit 1,
	// lockoutAuthSet bit 2, inLockout bit 9.
	info.OwnerAuthSet = perm&(1<<0) != 0
	info.LockoutAuthSet = perm&(1<<2) != 0
	info.InLockout = perm&(1<<9) != 0
	return info, nil
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// ErrLockoutAuthSet means the lockout hierarchy already has a password.
var ErrLockoutAuthSet = errors.New("tpm: the lockout authorization is already set")

// ProtectLockout sets the TPM's lockout authorization to code, which must
// come from AuthValue (32 characters, no zero bytes). With an empty lockout
// authorization anyone with TPM access (root) can reset the dictionary-attack
// counter and guess PINs without limit; with it set, only the holder of the
// code can. The caller generates and shows the code before it is set, so it
// can never be lost on the way back; it is not stored anywhere.
func (k *TPM) ProtectLockout(code []byte) error {
	if len(code) != 32 || checkAuth(code) != nil {
		return errors.New("tpm: the lockout code must be 32 characters from AuthValue")
	}
	info, err := k.Info()
	if err != nil {
		return err
	}
	if info.LockoutAuthSet {
		return ErrLockoutAuthSet
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	_, err = tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHLockout,
			// A password session: the TPM authenticates the response of
			// HierarchyChangeAuth with the new value, which go-tpm's HMAC
			// sessions do not expect.
			Auth: tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{Buffer: code},
	}.Execute(k.t)
	return err
}
