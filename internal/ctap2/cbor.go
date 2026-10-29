package ctap2

import (
	"github.com/fxamacker/cbor/v2"
)

// CTAP status codes.
const (
	StatusOK                  = 0x00
	ErrInvalidCommand         = 0x01
	ErrInvalidParameter       = 0x02
	ErrInvalidLength          = 0x03
	ErrCBORUnexpectedType     = 0x11
	ErrInvalidCBOR            = 0x12
	ErrMissingParameter       = 0x14
	ErrLimitExceeded          = 0x15
	ErrCredentialExcluded     = 0x19
	ErrUnsupportedAlgorithm   = 0x26
	ErrOperationDenied        = 0x27
	ErrKeyStoreFull           = 0x28
	ErrUnsupportedOption      = 0x2B
	ErrInvalidOption          = 0x2C
	ErrKeepaliveCancel        = 0x2D
	ErrNoCredentials          = 0x2E
	ErrUserActionTimeout      = 0x2F
	ErrNotAllowed             = 0x30
	ErrPINInvalid             = 0x31
	ErrPINBlocked             = 0x32
	ErrPINAuthInvalid         = 0x33
	ErrPINAuthBlocked         = 0x34
	ErrPINNotSet              = 0x35
	ErrPUATRequired           = 0x36
	ErrPINPolicyViolation     = 0x37
	ErrRequestTooLarge        = 0x39
	ErrInvalidSubcommand      = 0x3E
	ErrUnauthorizedPermission = 0x40
	ErrOther                  = 0x7F
)

// Error is a CTAP status returned to the platform.
type Error byte

func (e Error) Error() string { return "ctap2: status 0x" + hex2(byte(e)) }

func hex2(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&15]})
}

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	// CTAP2 canonical CBOR: shortest forms, length-first sorted map keys,
	// no indefinite lengths, no tags.
	encMode, err = cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  8,
		MaxArrayElements: 1024,
		MaxMapPairs:      256,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// CBOR major types.
const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorSimple = 7
)

func major(raw cbor.RawMessage) int {
	if len(raw) == 0 {
		return -1
	}
	return int(raw[0] >> 5)
}

type intMap map[int]cbor.RawMessage
type strMap map[string]cbor.RawMessage

// parseIntMap decodes a CBOR map with integer keys, as every CTAP command's
// parameters are.
func parseIntMap(data []byte) (intMap, error) {
	if len(data) == 0 {
		return intMap{}, nil
	}
	if major(data) != majorMap {
		return nil, Error(ErrCBORUnexpectedType)
	}
	var m intMap
	if rest, err := decMode.UnmarshalFirst(data, &m); err != nil || len(rest) != 0 {
		return nil, Error(ErrInvalidCBOR)
	}
	return m, nil
}

func decodeRaw(raw cbor.RawMessage, want int, out any) error {
	if major(raw) != want {
		return Error(ErrCBORUnexpectedType)
	}
	if err := decMode.Unmarshal(raw, out); err != nil {
		return Error(ErrInvalidCBOR)
	}
	return nil
}

func (m intMap) bytes(k int) ([]byte, bool, error) {
	raw, ok := m[k]
	if !ok {
		return nil, false, nil
	}
	var b []byte
	if err := decodeRaw(raw, majorBytes, &b); err != nil {
		return nil, true, err
	}
	if b == nil {
		b = []byte{}
	}
	return b, true, nil
}

func (m intMap) text(k int) (string, bool, error) {
	raw, ok := m[k]
	if !ok {
		return "", false, nil
	}
	var s string
	err := decodeRaw(raw, majorText, &s)
	return s, true, err
}

func (m intMap) uint(k int) (uint64, bool, error) {
	raw, ok := m[k]
	if !ok {
		return 0, false, nil
	}
	var u uint64
	err := decodeRaw(raw, majorUint, &u)
	return u, true, err
}

func (m intMap) strMap(k int) (strMap, bool, error) {
	raw, ok := m[k]
	if !ok {
		return nil, false, nil
	}
	var sm strMap
	err := decodeRaw(raw, majorMap, &sm)
	return sm, true, err
}

func (m intMap) intMap(k int) (intMap, bool, error) {
	raw, ok := m[k]
	if !ok {
		return nil, false, nil
	}
	var im intMap
	err := decodeRaw(raw, majorMap, &im)
	return im, true, err
}

func (m intMap) array(k int) ([]cbor.RawMessage, bool, error) {
	raw, ok := m[k]
	if !ok {
		return nil, false, nil
	}
	var a []cbor.RawMessage
	err := decodeRaw(raw, majorArray, &a)
	return a, true, err
}

func (m strMap) text(k string) (string, bool, error) {
	raw, ok := m[k]
	if !ok {
		return "", false, nil
	}
	var s string
	err := decodeRaw(raw, majorText, &s)
	return s, true, err
}

func (m strMap) bytes(k string) ([]byte, bool, error) {
	raw, ok := m[k]
	if !ok {
		return nil, false, nil
	}
	var b []byte
	if err := decodeRaw(raw, majorBytes, &b); err != nil {
		return nil, true, err
	}
	if b == nil {
		b = []byte{}
	}
	return b, true, nil
}

func (m strMap) boolean(k string) (bool, bool, error) {
	raw, ok := m[k]
	if !ok {
		return false, false, nil
	}
	if major(raw) != majorSimple || len(raw) != 1 || (raw[0] != 0xf4 && raw[0] != 0xf5) {
		return false, true, Error(ErrCBORUnexpectedType)
	}
	return raw[0] == 0xf5, true, nil
}

// options decodes an options map. Unknown keys are ignored, as the spec
// demands; known keys must be booleans.
func options(raw strMap) (map[string]bool, error) {
	out := map[string]bool{}
	for k := range raw {
		switch k {
		case "rk", "up", "uv":
			v, _, err := raw.boolean(k)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
	}
	return out, nil
}

// descriptor is a PublicKeyCredentialDescriptor.
type descriptor struct {
	Type string
	ID   []byte
}

func parseDescriptor(raw cbor.RawMessage) (descriptor, error) {
	var m strMap
	if err := decodeRaw(raw, majorMap, &m); err != nil {
		return descriptor{}, err
	}
	typ, ok, err := m.text("type")
	if err != nil {
		return descriptor{}, err
	}
	if !ok {
		return descriptor{}, Error(ErrMissingParameter)
	}
	id, ok, err := m.bytes("id")
	if err != nil {
		return descriptor{}, err
	}
	if !ok {
		return descriptor{}, Error(ErrMissingParameter)
	}
	return descriptor{Type: typ, ID: id}, nil
}

func parseDescriptors(list []cbor.RawMessage) ([]descriptor, error) {
	out := make([]descriptor, 0, len(list))
	for _, raw := range list {
		d, err := parseDescriptor(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func encode(v any) []byte {
	b, err := encMode.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
