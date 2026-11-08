package protocol

import (
	"fmt"
	"io"
)

// RequestHeader is the VLESS request header.
//
//	+--------+-------------------------------+
//	| 1 byte | version (0)                   |
//	|16 bytes| UUID                          |
//	| 1 byte | addons length (0..255)        |
//	| N bytes| addons (protobuf)             |
//	| 1 byte | command                       |
//	| 2 bytes| port, big endian              |  \
//	| 1 byte | address type                  |   | omitted for Mux / Rvs
//	| N bytes| address                       |  /
//	+--------+-------------------------------+
type RequestHeader struct {
	Version byte
	UUID    UUID
	Addons  *Addons
	Command Command
	Address Address
}

// ResponseHeader is the VLESS response header. The payload follows immediately.
//
//	+--------+-------------------------------+
//	| 1 byte | version (same as request)     |
//	| 1 byte | addons length (0..255)        |
//	| N bytes| addons (protobuf)             |
//	+--------+-------------------------------+
type ResponseHeader struct {
	Version byte
	Addons  *Addons
}

// Validator resolves a wire UUID to a user. Xray-core calls this the
// "validator"; implementations should normalize the UUID before lookup (see
// NormalizeUUID) to stay compatible with clients that use the routing bytes.
type Validator interface {
	Get(UUID) (string, bool)
}

// ValidatorFunc adapts a plain function into a Validator.
type ValidatorFunc func(UUID) (string, bool)

func (f ValidatorFunc) Get(u UUID) (string, bool) { return f(u) }

// WriteRequestHeader emits the complete request header in a single write.
func WriteRequestHeader(w io.Writer, h *RequestHeader) error {
	if h == nil {
		return ErrBadAddress
	}
	if h.Version != Version {
		return fmt.Errorf("%w: %d", ErrVersion, h.Version)
	}
	switch h.Command {
	case CommandTCP, CommandUDP, CommandMux, CommandRvs:
	default:
		return fmt.Errorf("%w: %d", ErrBadCommand, h.Command)
	}

	var b []byte
	b = append(b, h.Version)
	b = append(b, h.UUID[:]...)

	addons := MarshalAddons(h.Addons)
	if len(addons) > MaxAddonsLength {
		return ErrAddonsTooLong
	}
	b = append(b, byte(len(addons)))
	b = append(b, addons...)

	b = append(b, byte(h.Command))
	if h.Command.HasAddress() {
		var err error
		b, err = AppendAddressPort(b, h.Address)
		if err != nil {
			return err
		}
	}
	return writeAll(w, b)
}

// ReadRequestHeader reads and validates a request header. A nil Validator
// skips user verification, which is useful for pure parsing / testing.
func ReadRequestHeader(r io.Reader, v Validator) (*RequestHeader, error) {
	h := &RequestHeader{}

	var one [1]byte
	if _, err := io.ReadFull(r, one[:]); err != nil {
		return nil, err
	}
	h.Version = one[0]
	if h.Version != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, h.Version)
	}

	if _, err := io.ReadFull(r, h.UUID[:]); err != nil {
		return nil, err
	}
	if v != nil {
		if _, ok := v.Get(h.UUID); !ok {
			return nil, fmt.Errorf("%w: %s", ErrUserRejected, h.UUID.String())
		}
	}

	if _, err := io.ReadFull(r, one[:]); err != nil {
		return nil, err
	}
	n := int(one[0])
	if n > 0 {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		addons, err := UnmarshalAddons(b)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadAddons, err)
		}
		h.Addons = addons
	} else {
		h.Addons = &Addons{}
	}

	if _, err := io.ReadFull(r, one[:]); err != nil {
		return nil, err
	}
	h.Command = Command(one[0])
	switch h.Command {
	case CommandTCP, CommandUDP:
		addr, err := ReadAddressPort(r)
		if err != nil {
			return nil, err
		}
		h.Address = addr
	case CommandMux:
		h.Address = Address{Domain: MuxDomain}
	case CommandRvs:
		h.Address = Address{Domain: RvsDomain}
	default:
		return nil, fmt.Errorf("%w: %d", ErrBadCommand, one[0])
	}
	return h, nil
}

// WriteResponseHeader emits the response header.
func WriteResponseHeader(w io.Writer, h *ResponseHeader) error {
	if h == nil {
		return ErrVersion
	}
	addons := MarshalAddons(h.Addons)
	if len(addons) > MaxAddonsLength {
		return ErrAddonsTooLong
	}
	b := make([]byte, 0, 2+len(addons))
	b = append(b, h.Version, byte(len(addons)))
	b = append(b, addons...)
	return writeAll(w, b)
}

// ReadResponseHeader reads the response header and checks its version against
// the version the client sent.
func ReadResponseHeader(r io.Reader, expectedVersion byte) (*ResponseHeader, error) {
	h := &ResponseHeader{}
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	h.Version = head[0]
	if h.Version != expectedVersion {
		return nil, fmt.Errorf("%w: want %d, got %d", ErrResponseVersion, expectedVersion, h.Version)
	}
	n := int(head[1])
	if n > 0 {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		addons, err := UnmarshalAddons(b)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadAddons, err)
		}
		h.Addons = addons
	} else {
		h.Addons = &Addons{}
	}
	return h, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
