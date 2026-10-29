package ctap2

import (
	"bytes"

	"github.com/Divanyx/omapasskey/internal/pinuv"
	"github.com/Divanyx/omapasskey/internal/vault"
)

// authenticatorCredentialManagement subcommands.
const (
	cmGetCredsMetadata      = 0x01
	cmEnumerateRPsBegin     = 0x02
	cmEnumerateRPsNext      = 0x03
	cmEnumerateCredsBegin   = 0x04
	cmEnumerateCredsNext    = 0x05
	cmDeleteCredential      = 0x06
	cmUpdateUserInformation = 0x07
)

type rpEntry struct {
	id, name string
	hash     []byte
}

type rpEnumeration struct {
	rps  []rpEntry
	next int
}

type credEnumeration struct {
	items []map[int]any
	next  int
}

func (a *Authenticator) credentialManagement(r *request, params []byte) (any, error) {
	m, err := parseIntMap(params)
	if err != nil {
		return nil, err
	}
	sub, ok, err := m.uint(1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Error(ErrMissingParameter)
	}
	// The continuations carry no authentication; they only page through
	// what the authenticated "begin" call already decided to reveal.
	switch sub {
	case cmEnumerateRPsNext:
		e := a.enumRPs
		a.enumCreds = nil
		if e == nil || e.next >= len(e.rps) {
			a.enumRPs = nil
			return nil, Error(ErrNotAllowed)
		}
		rp := e.rps[e.next]
		e.next++
		return map[int]any{3: rpMap(rp), 4: rp.hash}, nil
	case cmEnumerateCredsNext:
		e := a.enumCreds
		a.enumRPs = nil
		if e == nil || e.next >= len(e.items) {
			a.enumCreds = nil
			return nil, Error(ErrNotAllowed)
		}
		item := e.items[e.next]
		e.next++
		return item, nil
	}
	a.enumRPs, a.enumCreds = nil, nil

	subParamsRaw := m[2]
	var subParams intMap
	if subParamsRaw != nil {
		if err := decodeRaw(subParamsRaw, majorMap, &subParams); err != nil {
			return nil, err
		}
	}
	param, hasParam, err := m.bytes(4)
	if err != nil {
		return nil, err
	}
	if !hasParam {
		return nil, Error(ErrPUATRequired)
	}
	protocol, hasProtocol, err := m.uint(3)
	if err != nil {
		return nil, err
	}
	if !hasProtocol {
		return nil, Error(ErrMissingParameter)
	}
	if pinuv.ByVersion(protocol) == nil {
		return nil, Error(ErrInvalidParameter)
	}
	switch sub {
	case cmGetCredsMetadata, cmEnumerateRPsBegin, cmEnumerateCredsBegin, cmDeleteCredential, cmUpdateUserInformation:
	default:
		return nil, Error(ErrInvalidSubcommand)
	}
	msg := append([]byte{byte(sub)}, subParamsRaw...)
	t, err := a.verifyToken(protocol, msg, param)
	if err != nil {
		return nil, err
	}
	if t.permissions&permCM == 0 {
		return nil, Error(ErrPINAuthInvalid)
	}
	u := t.unlocked

	switch sub {
	case cmGetCredsMetadata:
		if t.hasRPID {
			return nil, Error(ErrPINAuthInvalid)
		}
		disc, _ := a.vault.Counts()
		return map[int]any{1: disc, 2: vault.MaxDiscoverable - disc}, nil

	case cmEnumerateRPsBegin:
		if t.hasRPID {
			return nil, Error(ErrPINAuthInvalid)
		}
		rps, err := a.relyingParties(u)
		if err != nil {
			return nil, err
		}
		if len(rps) == 0 {
			return nil, Error(ErrNoCredentials)
		}
		if len(rps) > 1 {
			a.enumRPs = &rpEnumeration{rps: rps, next: 1}
		}
		return map[int]any{3: rpMap(rps[0]), 4: rps[0].hash, 5: len(rps)}, nil

	case cmEnumerateCredsBegin:
		hash, ok, err := subParams.bytes(1)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, Error(ErrMissingParameter)
		}
		if t.hasRPID && !bytes.Equal(rpHash(t.rpID), hash) {
			return nil, Error(ErrPINAuthInvalid)
		}
		creds := a.vault.Discoverable(hash)
		if len(creds) == 0 {
			return nil, Error(ErrNoCredentials)
		}
		items := make([]map[int]any, 0, len(creds))
		for _, c := range creds {
			acct, err := a.vault.Account(u, c)
			if err != nil {
				return nil, Error(ErrOther)
			}
			user := map[string]any{"id": acct.UserID}
			if acct.UserName != "" {
				user["name"] = acct.UserName
			}
			if acct.DisplayName != "" {
				user["displayName"] = acct.DisplayName
			}
			items = append(items, map[int]any{
				6:  user,
				7:  map[string]any{"id": c.ID, "type": "public-key"},
				8:  coseKeyMap(c.PublicX, c.PublicY),
				10: c.CredProtect,
			})
		}
		first := items[0]
		first[9] = len(items)
		if len(items) > 1 {
			a.enumCreds = &credEnumeration{items: items, next: 1}
		}
		return first, nil

	case cmDeleteCredential, cmUpdateUserInformation:
		descRaw, ok := subParams[2]
		if !ok {
			return nil, Error(ErrMissingParameter)
		}
		d, err := parseDescriptor(descRaw)
		if err != nil {
			return nil, err
		}
		c := a.vault.FindByID(d.ID)
		if c == nil {
			return nil, Error(ErrNoCredentials)
		}
		if t.hasRPID && !bytes.Equal(rpHash(t.rpID), c.RPIDHash) {
			return nil, Error(ErrPINAuthInvalid)
		}
		if sub == cmDeleteCredential {
			if err := a.vault.Delete(c.ID); err != nil {
				return nil, Error(ErrOther)
			}
			if a.events != nil {
				a.events.Done("delete", "", true)
			}
			return nil, nil
		}
		userMap, ok, err := subParams.strMap(3)
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
		acct, err := a.vault.Account(u, c)
		if err != nil {
			return nil, Error(ErrOther)
		}
		if !bytes.Equal(acct.UserID, user.ID) {
			return nil, Error(ErrInvalidParameter)
		}
		if err := a.vault.UpdateAccount(u, c.ID, user.Name, user.DisplayName); err != nil {
			return nil, Error(ErrOther)
		}
		return nil, nil
	}
	return nil, Error(ErrInvalidSubcommand)
}

// relyingParties lists the RPs that have discoverable credentials.
func (a *Authenticator) relyingParties(u *vault.Unlocked) ([]rpEntry, error) {
	var out []rpEntry
	for _, c := range a.vault.Discoverable(nil) {
		seen := false
		for _, rp := range out {
			if bytes.Equal(rp.hash, c.RPIDHash) {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		acct, err := a.vault.Account(u, c)
		if err != nil {
			return nil, Error(ErrOther)
		}
		out = append(out, rpEntry{id: acct.RPID, name: acct.RPName, hash: c.RPIDHash})
	}
	return out, nil
}

func rpMap(rp rpEntry) map[string]any {
	m := map[string]any{"id": rp.id}
	if rp.name != "" {
		m["name"] = rp.name
	}
	return m
}
