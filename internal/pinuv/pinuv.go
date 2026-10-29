// Package pinuv implements the CTAP2 PIN/UV auth protocols one and two: the
// ECDH key agreement with the platform and the AES/HMAC operations built on it.
package pinuv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

// Protocol is one PIN/UV auth protocol.
type Protocol interface {
	Version() uint64
	// KDF turns the ECDH x-coordinate into the shared secret.
	KDF(z []byte) ([]byte, error)
	Encrypt(key, plaintext []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
	Authenticate(key, message []byte) []byte
	Verify(key, message, signature []byte) bool
}

// ErrBadCiphertext is returned for ciphertexts of an impossible length.
var ErrBadCiphertext = errors.New("pinuv: bad ciphertext")

// One is PIN/UV auth protocol one.
type One struct{}

// Two is PIN/UV auth protocol two.
type Two struct{}

// ByVersion returns the protocol with the given number, or nil.
func ByVersion(v uint64) Protocol {
	switch v {
	case 1:
		return One{}
	case 2:
		return Two{}
	}
	return nil
}

func (One) Version() uint64 { return 1 }

func (One) KDF(z []byte) ([]byte, error) {
	h := sha256.Sum256(z)
	return h[:], nil
}

func (One) Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 || len(plaintext)%aes.BlockSize != 0 {
		return nil, ErrBadCiphertext
	}
	return cbc(key, make([]byte, aes.BlockSize), plaintext, true)
}

func (One) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrBadCiphertext
	}
	return cbc(key, make([]byte, aes.BlockSize), ciphertext, false)
}

func (One) Authenticate(key, message []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(message)
	return m.Sum(nil)[:16]
}

func (p One) Verify(key, message, signature []byte) bool {
	if len(signature) != 16 {
		return false
	}
	return subtle.ConstantTimeCompare(p.Authenticate(key, message), signature) == 1
}

func (Two) Version() uint64 { return 2 }

// KDF yields 64 bytes: the HMAC key followed by the AES key.
func (Two) KDF(z []byte) ([]byte, error) {
	salt := make([]byte, 32)
	hmacKey, err := hkdf.Key(sha256.New, z, salt, "CTAP2 HMAC key", 32)
	if err != nil {
		return nil, err
	}
	aesKey, err := hkdf.Key(sha256.New, z, salt, "CTAP2 AES key", 32)
	if err != nil {
		return nil, err
	}
	return append(hmacKey, aesKey...), nil
}

// twoAESKey selects the AES half of a protocol-two shared secret.
func twoAESKey(key []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, ErrBadCiphertext
	}
	return key[32:], nil
}

func (Two) Encrypt(key, plaintext []byte) ([]byte, error) {
	k, err := twoAESKey(key)
	if err != nil || len(plaintext)%aes.BlockSize != 0 {
		return nil, ErrBadCiphertext
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct, err := cbc(k, iv, plaintext, true)
	if err != nil {
		return nil, err
	}
	return append(iv, ct...), nil
}

func (Two) Decrypt(key, ciphertext []byte) ([]byte, error) {
	k, err := twoAESKey(key)
	if err != nil || len(ciphertext) < 2*aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrBadCiphertext
	}
	return cbc(k, ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:], false)
}

func (Two) Authenticate(key, message []byte) []byte {
	if len(key) > 32 {
		key = key[:32]
	}
	m := hmac.New(sha256.New, key)
	m.Write(message)
	return m.Sum(nil)
}

func (p Two) Verify(key, message, signature []byte) bool {
	if len(signature) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(p.Authenticate(key, message), signature) == 1
}

func cbc(key, iv, in []byte, encrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(in))
	if encrypt {
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, in)
	} else {
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, in)
	}
	return out, nil
}

// KeyAgreement is the authenticator's ephemeral P-256 key.
type KeyAgreement struct {
	priv *ecdh.PrivateKey
}

// NewKeyAgreement generates a fresh key.
func NewKeyAgreement() (*KeyAgreement, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyAgreement{priv: k}, nil
}

// COSE returns the public key as a COSE_Key map for getKeyAgreement:
// kty EC2, alg ECDH-ES+HKDF-256 (-25), crv P-256.
func (k *KeyAgreement) COSE() map[int]any {
	raw := k.priv.PublicKey().Bytes() // 0x04 || X || Y
	return map[int]any{
		1:  2,
		3:  -25,
		-1: 1,
		-2: raw[1:33],
		-3: raw[33:65],
	}
}

// SharedSecret runs ECDH against the platform's public key (given as the COSE
// x and y coordinates) and applies the protocol's KDF.
func (k *KeyAgreement) SharedSecret(p Protocol, x, y []byte) ([]byte, error) {
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("pinuv: bad platform key")
	}
	pub, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, err
	}
	z, err := k.priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return p.KDF(z)
}
