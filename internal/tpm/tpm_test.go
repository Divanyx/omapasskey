package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func openSim(t *testing.T) *TPM {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	k, err := New(sim)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close() })
	return k
}

func TestSealUnseal(t *testing.T) {
	k := openSim(t)
	secret := bytes.Repeat([]byte{7}, 32)
	auth := []byte("correct horse battery staple 123")
	b, err := k.Seal(secret, auth)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Unseal(b, auth)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("unsealed %x, want %x", got, secret)
	}
	if _, err := k.Unseal(b, []byte("wrong")); !errors.Is(err, ErrBadAuth) {
		t.Fatalf("wrong auth: got %v, want ErrBadAuth", err)
	}
	info, err := k.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.LockoutCounter == 0 {
		t.Fatalf("a wrong auth value did not count towards the lockout: %+v", info)
	}
}

func TestSignVerifies(t *testing.T) {
	k := openSim(t)
	auth := bytes.Repeat([]byte{1}, 32)
	b, x, y, err := k.CreateSigningKey(auth)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hello"))
	r, s, err := k.Sign(b, auth, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)) {
		t.Fatal("TPM signature does not verify")
	}
	if _, _, err := k.Sign(b, []byte("nope"), digest[:]); !errors.Is(err, ErrBadAuth) {
		t.Fatalf("wrong auth: got %v, want ErrBadAuth", err)
	}
}

func TestHMACIsStable(t *testing.T) {
	k := openSim(t)
	auth := bytes.Repeat([]byte{2}, 32)
	b, err := k.CreateHMACKey(auth)
	if err != nil {
		t.Fatal(err)
	}
	a1, err := k.HMAC(b, auth, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := k.HMAC(b, auth, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := k.HMAC(b, auth, []byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1, a2) || bytes.Equal(a1, other) || len(a1) != 32 {
		t.Fatalf("hmac outputs unstable or wrong size: %x %x %x", a1, a2, other)
	}
	// The key is not some fixed value: a second key gives other outputs.
	b2, err := k.CreateHMACKey(auth)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := k.HMAC(b2, auth, []byte("salt"))
	if bytes.Equal(a1, c) {
		t.Fatal("two HMAC keys produced the same output")
	}
	mac := hmac.New(sha256.New, nil)
	if bytes.Equal(mac.Sum(nil), a1) {
		t.Fatal("hmac with empty key")
	}
}
