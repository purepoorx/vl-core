package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Address is a destination address plus port. Exactly one of Domain / IP is
// set; keeping the distinction matters because the wire encodes them with
// different address type bytes and because domain names must be resolved by
// the server, not by the client.
type Address struct {
	Domain string
	IP     net.IP
	Port   uint16
}

func (a Address) IsDomain() bool { return a.Domain != "" }

func (a Address) Host() string {
	if a.Domain != "" {
		return a.Domain
	}
	return a.IP.String()
}

func (a Address) String() string {
	return net.JoinHostPort(a.Host(), strconv.Itoa(int(a.Port)))
}

// ParseAddress classifies host as an IP literal or a domain name.
func ParseAddress(host string, port uint16) Address {
	a := Address{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			a.IP = net.IP(append([]byte(nil), v4...))
		} else {
			a.IP = net.IP(append([]byte(nil), ip.To16()...))
		}
	} else {
		a.Domain = host
	}
	return a
}

func (a Address) Validate() error {
	if a.Domain != "" {
		if len(a.Domain) > MaxDomainLength {
			return ErrDomainTooLong
		}
		if !isValidDomain(a.Domain) {
			return ErrDomainInvalid
		}
		return nil
	}
	if a.IP == nil || (a.IP.To4() == nil && a.IP.To16() == nil) {
		return ErrBadAddress
	}
	return nil
}

// isValidDomain mirrors Xray-core's common/protocol.isValidDomain.
func isValidDomain(d string) bool {
	if len(d) == 0 {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// AppendAddressPort appends "port (2, big endian) + type byte + address bytes".
func AppendAddressPort(dst []byte, a Address) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return dst, err
	}
	dst = append(dst, byte(a.Port>>8), byte(a.Port))
	switch {
	case a.Domain != "":
		dst = append(dst, AddressTypeDomain, byte(len(a.Domain)))
		return append(dst, a.Domain...), nil
	case a.IP.To4() != nil:
		dst = append(dst, AddressTypeIPv4)
		return append(dst, a.IP.To4()...), nil
	default:
		dst = append(dst, AddressTypeIPv6)
		return append(dst, a.IP.To16()...), nil
	}
}

func WriteAddressPort(w io.Writer, a Address) error {
	b, err := AppendAddressPort(nil, a)
	if err != nil {
		return err
	}
	return writeAll(w, b)
}

func ReadAddressPort(r io.Reader) (Address, error) {
	var a Address
	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return a, err
	}
	a.Port = binary.BigEndian.Uint16(portBytes[:])

	var one [1]byte
	if _, err := io.ReadFull(r, one[:]); err != nil {
		return a, err
	}
	switch one[0] {
	case AddressTypeIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return a, err
		}
		a.IP = net.IP(b)
	case AddressTypeIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return a, err
		}
		a.IP = net.IP(b)
	case AddressTypeDomain:
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return a, err
		}
		n := int(one[0])
		if n == 0 {
			return a, ErrBadAddress
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return a, err
		}
		domain := string(b)
		// Xray-core converts numeric-looking domains back into IP addresses.
		if ip := net.ParseIP(domain); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				a.IP = net.IP(append([]byte(nil), v4...))
			} else {
				a.IP = net.IP(append([]byte(nil), ip.To16()...))
			}
		} else if !isValidDomain(domain) {
			return a, fmt.Errorf("%w: %q", ErrDomainInvalid, domain)
		} else {
			a.Domain = domain
		}
	default:
		return a, fmt.Errorf("%w: %d", ErrBadAddressType, one[0])
	}
	return a, nil
}
