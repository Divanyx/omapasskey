package ctap2

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"math/big"

	"github.com/fxamacker/cbor/v2"

	"github.com/Divanyx/omapasskey/internal/pinuv"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// authenticator data flags.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
	flagED = 0x80
)

const maxUserIDLength = 64

type userEntity struct {
	ID          []byte
	Name        string
	DisplayName string
}

func parseUser(raw strMap) (userEntity, error) {
	var u userEntity
	id, ok, err := raw.bytes("id")
	if err != nil {
		return u, err
	}
	if !ok {
		return u, Error(ErrMissingParameter)
	}
	if len(id) > maxUserIDLength {
		return u, Error(ErrInvalidParameter)
	}
	u.ID = id
	if u.Name, _, err = raw.text("name"); err != nil {
		return u, err
	}
	if u.DisplayName, _, err = raw.text("displayName"); err != nil {
		return u, err
	}
	return u, nil
}

func (a *Authenticator) makeCredential(r *request, params []byte) (any, error) {
	m, err := parseIntMap(params)
	if err != nil {
		return nil, err
	}
	clientDataHash, ok, err := m.bytes(1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	rpMap, ok, err := m.strMap(2)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	rpID, ok, err := rpMap.text("id")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	rpName, _, err := rpMap.text("name")
	if err != nil {
		return nil, err
	}
	userMap, ok, err := m.strMap(3)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	user, err := parseUser(userMap)
	if err != nil {
		return nil, err
	}
	credParams, ok, err := m.array(4)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	excludeRaw, _, err := m.array(5)
	if err != nil {
		return nil, err
	}
	exclude, err := parseDescriptors(excludeRaw)
	if err != nil {
		return nil, err
	}
	extMap, _, err := m.strMap(6)
	if err != nil {
		return nil, err
	}
	optMap, _, err := m.strMap(7)
	if err != nil {
		return nil, err
	}
	opts, err := options(optMap)
	if err != nil {
		return nil, err
	}
	pinUvAuthParam, hasParam, err := m.bytes(8)
	if err != nil {
		return nil, err
	}
	protocol, hasProtocol, err := m.uint(9)
	if err != nil {
		return nil, err
	}

	// Step 1: a zero-length pinUvAuthParam asks for a touch to pick this key.
	if hasParam && len(pinUvAuthParam) == 0 {
		if err := a.confirm(r, Prompt{Op: "select"}, false); err != nil {
			return nil, err
		}
		if a.vault.PINSet() {
			return nil, Error(ErrPINInvalid)
		}
		return nil, Error(ErrPINNotSet)
	}
	// Step 2.
	if hasParam {
		if !hasProtocol {
			return nil, Error(ErrMissingParameter)
		}
		if pinuv.ByVersion(protocol) == nil {
			return nil, Error(ErrInvalidParameter)
		}
	}
	// Step 3: only ES256 on P-256 exists in the TPM.
	chosen := false
	for _, raw := range credParams {
		var p strMap
		if err := decodeRaw(raw, majorMap, &p); err != nil {
			return nil, err
		}
		typ, ok1, err := p.text("type")
		if err != nil {
			return nil, err
		}
		algRaw, ok2 := p["alg"]
		if !ok1 || !ok2 {
			return nil, Error(ErrMissingParameter)
		}
		var alg int64
		if major(algRaw) != majorUint && major(algRaw) != majorNegInt {
			return nil, Error(ErrCBORUnexpectedType)
		}
		if err := decMode.Unmarshal(algRaw, &alg); err != nil {
			return nil, Error(ErrInvalidCBOR)
		}
		if typ == "public-key" && alg == -7 {
			chosen = true
		}
	}
	if !chosen {
		return nil, Error(ErrUnsupportedAlgorithm)
	}
	// Step 5: there is no built-in UV, so "uv" cannot be honoured.
	if opts["uv"] && !hasParam {
		return nil, Error(ErrInvalidOption)
	}
	if up, ok := opts["up"]; ok && !up {
		return nil, Error(ErrInvalidOption)
	}
	rk := opts["rk"]
	// Step 6: alwaysUv. Nothing is created without the PIN.
	if !a.vault.PINSet() || !hasParam {
		return nil, Error(ErrPUATRequired)
	}
	// Step 7.
	if _, ok := m[10]; ok {
		return nil, Error(ErrInvalidParameter)
	}
	if len(clientDataHash) != 32 {
		return nil, Error(ErrInvalidLength)
	}
	// Step 11: the token.
	t, err := a.verifyToken(protocol, clientDataHash, pinUvAuthParam)
	if err != nil {
		return nil, err
	}
	if t.permissions&permMC == 0 || !t.userVerified {
		return nil, Error(ErrPINAuthInvalid)
	}
	if t.hasRPID && t.rpID != rpID {
		return nil, Error(ErrPINAuthInvalid)
	}
	if !t.hasRPID {
		t.rpID, t.hasRPID = rpID, true
	}
	present := t.present()
	unlocked := t.unlocked.Clone()
	defer unlocked.Wipe()

	// Step 12: an already registered credential ends here, after a touch.
	hash := rpHash(rpID)
	for _, d := range exclude {
		if d.Type != "public-key" {
			continue
		}
		if a.vault.Find(d.ID, hash) == nil {
			continue
		}
		if !present {
			a.confirm(r, Prompt{Op: "exclude", RPID: rpID}, false)
		}
		a.consumeToken()
		return nil, Error(ErrCredentialExcluded)
	}
	// Step 14: user presence.
	if !present {
		if err := a.confirm(r, Prompt{Op: "register", RPID: rpID}, false); err != nil {
			return nil, err
		}
	}
	a.consumeToken()

	// Step 15: extensions.
	credProtect := 1
	wantHMAC := false
	extOut := map[string]any{}
	if v, ok := extMap["credProtect"]; ok {
		var level uint64
		if major(v) == majorUint && decMode.Unmarshal(v, &level) == nil && level >= 1 && level <= 3 {
			credProtect = int(level)
			extOut["credProtect"] = credProtect
		}
	}
	if b, ok, err := extMap.boolean("hmac-secret"); err == nil && ok && b {
		wantHMAC = true
	}

	r.status(0x01)
	cred, err := a.vault.NewCredential(unlocked, &vault.Account{
		RPID: rpID, RPName: rpName,
		UserID: user.ID, UserName: user.Name, DisplayName: user.DisplayName,
	}, rk, credProtect, wantHMAC)
	if err == vault.ErrFull {
		return nil, Error(ErrKeyStoreFull)
	}
	if err != nil {
		return nil, Error(ErrOther)
	}
	if wantHMAC {
		extOut["hmac-secret"] = true
	}

	flags := byte(flagUP | flagUV | flagAT)
	var extBytes []byte
	if len(extOut) > 0 {
		flags |= flagED
		extBytes = encode(extOut)
	}
	authData := make([]byte, 0, 37+16+2+len(cred.ID)+77+len(extBytes))
	authData = append(authData, hash...)
	authData = append(authData, flags)
	authData = append(authData, 0, 0, 0, 0) // signature counter: not kept
	authData = append(authData, a.cfg.AAGUID[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(cred.ID)))
	authData = append(authData, cred.ID...)
	authData = append(authData, coseKey(cred.PublicX, cred.PublicY)...)
	authData = append(authData, extBytes...)

	// Packed self-attestation: the new key signs its own registration.
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientDataHash...))
	sig, err := a.sign(unlocked, cred, digest[:])
	if err != nil {
		a.vault.Delete(cred.ID)
		return nil, Error(ErrOther)
	}
	if a.events != nil {
		a.events.Done("register", rpID, true)
	}
	return map[int]any{
		1: "packed",
		2: authData,
		3: map[string]any{"alg": -7, "sig": sig},
	}, nil
}

// coseKey encodes an ES256 public key with exactly the keys browsers expect.
func coseKey(x, y []byte) []byte {
	return encode(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
}

func coseKeyMap(x, y []byte) cbor.RawMessage {
	return cbor.RawMessage(coseKey(x, y))
}

func (a *Authenticator) sign(u *vault.Unlocked, c *vault.Credential, digest []byte) ([]byte, error) {
	rb, sb, err := a.vault.Sign(u, c, digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb)})
}
