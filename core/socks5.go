package core

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"vless-core/protocol"
)

// handleSocks5 implements RFC 1928 (no-auth) CONNECT and UDP ASSOCIATE.
func (c *Client) handleSocks5(local net.Conn) {
	br := bufio.NewReader(local)

	var greet [2]byte
	if _, err := io.ReadFull(br, greet[:]); err != nil || greet[0] != 0x05 {
		return
	}
	if greet[1] > 0 {
		if _, err := io.ReadFull(br, make([]byte, int(greet[1]))); err != nil {
			return
		}
	}
	if _, err := local.Write([]byte{0x05, 0x00}); err != nil { // NO AUTH
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != 0x05 {
		return
	}
	cmd, atyp := req[1], req[3]
	addr, err := readSocksAddress(br, atyp)
	if err != nil {
		_ = socksReply(local, 0x08, nil) // address type not supported
		return
	}

	switch cmd {
	case 0x01: // CONNECT
		c.socksConnect(local, br, addr)
	case 0x03: // UDP ASSOCIATE
		c.socksUDPAssociate(local, br)
	default:
		_ = socksReply(local, 0x07, nil) // command not supported
	}
}

func readSocksAddress(br *bufio.Reader, atyp byte) (protocol.Address, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return protocol.Address{}, err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		n, err := br.ReadByte()
		if err != nil {
			return protocol.Address{}, err
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(br, b); err != nil {
			return protocol.Address{}, err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return protocol.Address{}, err
		}
		host = net.IP(b).String()
	default:
		return protocol.Address{}, fmt.Errorf("unsupported socks address type %d", atyp)
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return protocol.Address{}, err
	}
	return protocol.ParseAddress(host, binary.BigEndian.Uint16(pb[:])), nil
}

func socksReply(w io.Writer, rep byte, bind *net.UDPAddr) error {
	buf := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if bind != nil {
		if ip4 := bind.IP.To4(); ip4 != nil {
			copy(buf[4:8], ip4)
		} else {
			buf = append([]byte{0x05, rep, 0x00, 0x04}, bind.IP.To16()...)
			buf = append(buf, 0, 0)
		}
		buf[len(buf)-2] = byte(bind.Port >> 8)
		buf[len(buf)-1] = byte(bind.Port)
	}
	_, err := w.Write(buf)
	return err
}

func (c *Client) socksConnect(local net.Conn, br *bufio.Reader, addr protocol.Address) {
	vc, err := c.openVLESS(context.Background(), addr, protocol.CommandTCP)
	if err != nil {
		c.log.Warn("vless dial %s failed: %v", addr.String(), err)
		_ = socksReply(local, 0x05, nil) // connection refused
		return
	}
	defer vc.Close()

	var bind *net.UDPAddr
	if ta, ok := local.LocalAddr().(*net.TCPAddr); ok {
		bind = &net.UDPAddr{IP: ta.IP, Port: ta.Port}
	}
	if err := socksReply(local, 0x00, bind); err != nil {
		return
	}
	c.log.Debug("socks CONNECT %s", addr.String())
	if err := c.relayTCP(local, br, vc); err != nil {
		c.log.Debug("socks session ended: %v", err)
	}
}

// socksUDPAssociate keeps the association alive for as long as its control TCP
// connection stays open, as required by RFC 1928.
func (c *Client) socksUDPAssociate(local net.Conn, br *bufio.Reader) {
	udp := c.UDPAddr()
	if udp == nil {
		_ = socksReply(local, 0x05, nil)
		return
	}
	advertise := &net.UDPAddr{IP: udp.IP, Port: udp.Port}
	if advertise.IP.IsUnspecified() {
		advertise.IP = net.IPv4(127, 0, 0, 1)
	}
	if err := socksReply(local, 0x00, advertise); err != nil {
		return
	}

	key := ""
	if ta, ok := local.RemoteAddr().(*net.TCPAddr); ok {
		key = ta.IP.String()
	}
	a := c.newAssociate(key)
	defer c.removeAssociate(a)

	c.log.Debug("socks UDP ASSOCIATE from %s (relay %s)", local.RemoteAddr(), advertise)
	_, _ = io.Copy(io.Discard, br)
}
