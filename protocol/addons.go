package protocol

// Addons is the proto3 message used in VLESS headers:
//
//	message Addons {
//	  string Flow = 1;
//	  bytes  Seed = 2;
//	}
//
// Xray-core encodes it with google.golang.org/protobuf. To keep this package
// dependency-free we implement just enough of the protobuf wire format here.
// Unknown fields are preserved verbatim in Raw so a header can be decoded and
// re-encoded without loss.
type Addons struct {
	Flow string
	Seed []byte
	Raw  []byte
}

func (a *Addons) IsEmpty() bool {
	return a == nil || (a.Flow == "" && len(a.Seed) == 0 && len(a.Raw) == 0)
}

// MarshalAddons serializes Addons into protobuf wire bytes. An empty Addons
// produces a zero-length slice, which encodes as a single 0x00 length byte.
func MarshalAddons(a *Addons) []byte {
	if a.IsEmpty() {
		return nil
	}
	var out []byte
	if a.Flow != "" {
		out = appendVarint(out, 1<<3|2)
		out = appendVarint(out, uint64(len(a.Flow)))
		out = append(out, a.Flow...)
	}
	if len(a.Seed) > 0 {
		out = appendVarint(out, 2<<3|2)
		out = appendVarint(out, uint64(len(a.Seed)))
		out = append(out, a.Seed...)
	}
	out = append(out, a.Raw...)
	return out
}

// UnmarshalAddons parses protobuf wire bytes. Only length-delimited fields are
// legal in the current Addons schema.
func UnmarshalAddons(b []byte) (*Addons, error) {
	a := &Addons{}
	for i := 0; i < len(b); {
		start := i
		tag, n := consumeVarint(b[i:])
		if n <= 0 {
			return nil, ErrBadAddons
		}
		i += n
		field, wire := tag>>3, tag&7
		if field == 0 || wire != 2 {
			return nil, ErrBadAddons
		}
		length, n := consumeVarint(b[i:])
		if n <= 0 {
			return nil, ErrBadAddons
		}
		i += n
		if length > uint64(len(b)-i) {
			return nil, ErrBadAddons
		}
		value := b[i : i+int(length)]
		i += int(length)
		switch field {
		case 1:
			a.Flow = string(value)
		case 2:
			a.Seed = append([]byte(nil), value...)
		default:
			a.Raw = append(a.Raw, b[start:i]...)
		}
	}
	return a, nil
}

func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// consumeVarint returns the value and the number of bytes consumed, or 0 on a
// malformed / truncated varint.
func consumeVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 10 && i < len(b); i++ {
		c := b[i]
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}
