package tpm

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// Regression: auth values with zero bytes failed about one time in eight
// (go-tpm v0.9.8 cut HMAC keys at the first zero). AuthValue never yields one.
func TestAuthValueAlwaysAuthorizes(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skip(err)
	}
	k, err := New(sim)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	for i := 0; i < 200; i++ {
		material := make([]byte, 24)
		rand.Read(material)
		if i == 0 {
			clear(material) // the worst case: all zeros
		}
		auth := AuthValue(material)
		if len(auth) != 32 || bytes.IndexByte(auth, 0) >= 0 {
			t.Fatalf("bad auth value %q", auth)
		}
		secret := make([]byte, 32)
		rand.Read(secret)
		b, err := k.Seal(secret, auth)
		if err != nil {
			t.Fatal(err)
		}
		got, err := k.Unseal(b, auth)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	if _, err := k.Seal([]byte{1}, []byte{1, 0, 1}); err == nil {
		t.Fatal("an auth value with a zero byte was accepted")
	}
}
