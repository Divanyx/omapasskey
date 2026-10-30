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

	"github.com/google/go-tpm/tpm2"
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

func TestProtectLockout(t *testing.T) {
	k := openSim(t)
	if err := k.ProtectLockout([]byte("short")); err == nil {
		t.Fatal("a malformed code was accepted")
	}
	code := AuthValue(bytes.Repeat([]byte{7}, 24))
	if err := k.ProtectLockout(code); err != nil {
		t.Fatal(err)
	}
	info, err := k.Info()
	if err != nil || !info.LockoutAuthSet {
		t.Fatalf("lockout auth not set: %+v %v", info, err)
	}
	if err := k.ProtectLockout(code); !errors.Is(err, ErrLockoutAuthSet) {
		t.Fatalf("second protect: %v", err)
	}
	// Sealing still works afterwards.
	b, err := k.Seal([]byte("x"), []byte("auth-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Unseal(b, []byte("auth-value")); err != nil {
		t.Fatal(err)
	}
}

// Review finding (marketplace #13302): with an empty lockout authorization,
// root can reset the dictionary-attack counter and keep guessing. This
// replays that attack (TPM2_DictionaryAttackLockReset with an empty
// password) before and after ProtectLockout.
func TestLockoutResetAttack(t *testing.T) {
	k := openSim(t)
	auth := []byte("pin-derived-auth")
	b, err := k.Seal([]byte("secret"), auth)
	if err != nil {
		t.Fatal(err)
	}
	// Three wrong guesses count against the TPM.
	for i := 0; i < 3; i++ {
		k.Unseal(b, []byte("wrong"))
	}
	before, _ := k.Info()
	if before.LockoutCounter == 0 {
		t.Fatal("wrong guesses did not count")
	}
	reset := func() error {
		k.mu.Lock()
		defer k.mu.Unlock()
		// TPM2_DictionaryAttackLockReset(TPM_RH_LOCKOUT) with an empty
		// password session; go-tpm v0.9.8 has no wrapper for it.
		cmd := []byte{0x80, 0x02, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x01, 0x39,
			0x40, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x09,
			0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00}
		rsp, err := k.t.Send(cmd)
		if err != nil {
			return err
		}
		if rc := tpm2.TPMRC(uint32(rsp[6])<<24 | uint32(rsp[7])<<16 | uint32(rsp[8])<<8 | uint32(rsp[9])); rc != 0 {
			return rc
		}
		return nil
	}
	// The attack works on an unprotected TPM ...
	if err := reset(); err != nil {
		t.Fatalf("reset with empty lockout auth failed unexpectedly: %v", err)
	}
	if info, _ := k.Info(); info.LockoutCounter != 0 {
		t.Fatalf("counter not reset: %d", info.LockoutCounter)
	}
	// ... and stops working once the lockout has a password.
	if err := k.ProtectLockout(AuthValue(bytes.Repeat([]byte{9}, 24))); err != nil {
		t.Fatal(err)
	}
	k.Unseal(b, []byte("wrong"))
	if err := reset(); err == nil {
		t.Fatal("root could still reset the counter after ProtectLockout")
	}
	if info, _ := k.Info(); info.LockoutCounter == 0 {
		t.Fatal("the counter was reset after ProtectLockout")
	}
}
