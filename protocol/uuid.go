package protocol

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// UUID is the 16-byte VLESS user identifier as it appears on the wire.
type UUID [16]byte

// ParseUUID accepts both the canonical hyphenated form and a bare 32 hex chars
// form. Xray-core accepts the same two forms.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	s = strings.TrimSpace(s)
	if len(s) == 36 {
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return u, fmt.Errorf("vless: malformed UUID %q", s)
		}
		s = s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	}
	if len(s) != 32 {
		return u, fmt.Errorf("vless: UUID must be 16 bytes, got %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return u, fmt.Errorf("vless: malformed UUID %q: %w", s, err)
	}
	copy(u[:], b)
	return u, nil
}

func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// NormalizeUUID mirrors Xray-core's vless.ProcessUUID. Bytes 6 and 7 of the
// UUID are used by clients to carry routing information (VlessRoute) and are
// deliberately ignored when looking up the user. Both the configured UUID and
// the wire UUID must be normalized before comparison, otherwise clients that
// use this feature would be rejected.
func NormalizeUUID(u UUID) UUID {
	u[6] = 0
	u[7] = 0
	return u
}

// Route returns the 16-bit value carried in the ignored UUID bytes.
func (u UUID) Route() uint16 {
	return uint16(u[6])<<8 | uint16(u[7])
}
