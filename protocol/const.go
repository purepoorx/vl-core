// Package protocol implements the VLESS protocol (version 0) wire format.
//
// It is a standalone, dependency-free reimplementation of the encoding layer
// found in Xray-core's proxy/vless/encoding. It has no knowledge of sockets,
// dispatchers or any Xray framework type: it only turns headers into bytes and
// bytes back into headers, so it can be embedded in any Go program.
package protocol

import "errors"

// Version is the only VLESS protocol version currently defined.
const Version byte = 0

// Command is the request command byte.
type Command byte

const (
	CommandTCP Command = 0x01
	CommandUDP Command = 0x02
	CommandMux Command = 0x03
	CommandRvs Command = 0x04
)

// IsStream reports whether the command carries a raw byte stream (as opposed
// to length-prefixed datagrams).
func (c Command) IsStream() bool {
	return c == CommandTCP || c == CommandMux || c == CommandRvs
}

// HasAddress reports whether a request of this command carries an address and
// port in its header. Mux/Rvs use well-known pseudo addresses instead.
func (c Command) HasAddress() bool {
	return c != CommandMux && c != CommandRvs
}

const (
	AddressTypeIPv4   byte = 1
	AddressTypeDomain byte = 2
	AddressTypeIPv6   byte = 3
)

// Flow values understood by Xray-core. This core implements the wire format
// for all of them but only the empty flow on the data plane (see README).
const (
	FlowNone         = ""
	FlowVision       = "xtls-rprx-vision"
	FlowVisionUDP443 = "xtls-rprx-vision-udp443"
)

const (
	MuxDomain = "v1.mux.cool"
	RvsDomain = "v1.rvs.cool"
)

const (
	MaxAddonsLength = 255 // addons length is a single byte on the wire
	MaxDomainLength = 255 // domain length is a single byte on the wire
	MaxPacketLength = 65535
)

var (
	ErrVersion         = errors.New("vless: unsupported protocol version")
	ErrBadAddressType  = errors.New("vless: unknown address type")
	ErrBadCommand      = errors.New("vless: unknown request command")
	ErrBadAddress      = errors.New("vless: invalid address")
	ErrBadAddons       = errors.New("vless: malformed addons")
	ErrAddonsTooLong   = errors.New("vless: addons exceed 255 bytes")
	ErrDomainTooLong   = errors.New("vless: domain exceeds 255 bytes")
	ErrDomainInvalid   = errors.New("vless: invalid domain name")
	ErrPacketTooLong   = errors.New("vless: udp packet exceeds 65535 bytes")
	ErrUserRejected    = errors.New("vless: invalid user id")
	ErrResponseVersion = errors.New("vless: unexpected response version")
)
