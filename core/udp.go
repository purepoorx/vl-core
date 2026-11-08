package core

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"vless-core/protocol"
)

// udpAssociate represents one SOCKS5 UDP ASSOCIATE control connection.
// Each distinct destination gets its own VLESS UDP connection (tunnel).
type udpAssociate struct {
	client     *Client
	key        string
	mu         sync.Mutex
	clientAddr *net.UDPAddr
	tunnels    map[string]*udpTunnel
	done       chan struct{}
	closeOnce  sync.Once
}

type udpTunnel struct {
	assoc     *udpAssociate
	target    protocol.Address
	conn      net.Conn
	br        *bufio.Reader
	bw        *bufio.Writer
	mu        sync.Mutex
	last      time.Time
	closeOnce sync.Once
}

func (c *Client) newAssociate(key string) *udpAssociate {
	a := &udpAssociate{
		client:  c,
		key:     key,
		tunnels: make(map[string]*udpTunnel),
		done:    make(chan struct{}),
	}
	c.mu.Lock()
	c.associates[key] = a
	c.mu.Unlock()
	go a.reapLoop()
	return a
}

func (c *Client) removeAssociate(a *udpAssociate) {
	c.mu.Lock()
	if c.associates[a.key] == a {
		delete(c.associates, a.key)
	}
	c.mu.Unlock()
	a.close()
}

func (c *Client) findAssociate(ip string) *udpAssociate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.associates[ip]
}

func (a *udpAssociate) reapLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	idle := a.client.cfg.UDPIdleTimeout()
	for {
		select {
		case <-a.done:
			return
		case <-ticker.C:
			a.mu.Lock()
			for key, t := range a.tunnels {
				t.mu.Lock()
				stale := time.Since(t.last) > idle
				t.mu.Unlock()
				if stale {
					delete(a.tunnels, key)
					t.close()
				}
			}
			a.mu.Unlock()
		}
	}
}

func (a *udpAssociate) close() {
	a.closeOnce.Do(func() {
		close(a.done)
		a.mu.Lock()
		for _, t := range a.tunnels {
			t.close()
		}
		a.tunnels = make(map[string]*udpTunnel)
		a.mu.Unlock()
	})
}

func (t *udpTunnel) close() {
	t.closeOnce.Do(func() { _ = t.conn.Close() })
}

func (t *udpTunnel) writePacket(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last = time.Now()
	if err := protocol.WritePacket(t.bw, p); err != nil {
		return err
	}
	return t.bw.Flush()
}

func (t *udpTunnel) readLoop() {
	key := t.target.String()
	defer func() {
		a := t.assoc
		a.mu.Lock()
		if a.tunnels[key] == t {
			delete(a.tunnels, key)
		}
		a.mu.Unlock()
		t.close()
	}()

	if _, err := protocol.ReadResponseHeader(t.br, protocol.Version); err != nil {
		t.assoc.client.log.Debug("udp tunnel %s: %v", key, err)
		return
	}
	for {
		pkt, err := protocol.ReadPacket(t.br)
		if err != nil {
			return
		}
		a := t.assoc
		a.mu.Lock()
		src := a.clientAddr
		a.mu.Unlock()
		if src == nil {
			continue
		}
		reply, err := buildSocksUDPReply(t.target, pkt)
		if err != nil {
			continue
		}
		a.client.mu.Lock()
		udpConn := a.client.udpConn
		a.client.mu.Unlock()
		if udpConn != nil {
			_, _ = udpConn.WriteToUDP(reply, src)
		}
	}
}

func (a *udpAssociate) getTunnel(addr protocol.Address) (*udpTunnel, error) {
	key := addr.String()
	a.mu.Lock()
	if t := a.tunnels[key]; t != nil {
		a.mu.Unlock()
		return t, nil
	}
	a.mu.Unlock()

	vc, err := a.client.openVLESS(context.Background(), addr, protocol.CommandUDP)
	if err != nil {
		return nil, err
	}
	t := &udpTunnel{
		assoc:  a,
		target: addr,
		conn:   vc.conn,
		br:     vc.br,
		bw:     vc.bw,
		last:   time.Now(),
	}
	a.mu.Lock()
	if existing := a.tunnels[key]; existing != nil {
		a.mu.Unlock()
		_ = vc.Close()
		return existing, nil
	}
	a.tunnels[key] = t
	a.mu.Unlock()
	go t.readLoop()
	return t, nil
}

func (c *Client) serveSocksUDP(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		go c.handleSocksUDPPacket(src, pkt)
	}
}

func (c *Client) handleSocksUDPPacket(src *net.UDPAddr, p []byte) {
	a := c.findAssociate(src.IP.String())
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.clientAddr == nil {
		a.clientAddr = src
	}
	a.mu.Unlock()

	addr, data, err := parseSocksUDPPayload(p)
	if err != nil {
		c.log.Debug("bad socks udp packet from %s: %v", src, err)
		return
	}
	if len(data) == 0 {
		return
	}
	t, err := a.getTunnel(addr)
	if err != nil {
		c.log.Warn("udp tunnel to %s failed: %v", addr.String(), err)
		return
	}
	if err := t.writePacket(data); err != nil {
		c.log.Debug("udp write %s: %v", addr.String(), err)
	}
}

// parseSocksUDPPayload decodes the SOCKS5 UDP request header:
//
//	RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA
func parseSocksUDPPayload(p []byte) (protocol.Address, []byte, error) {
	if len(p) < 5 {
		return protocol.Address{}, nil, fmt.Errorf("socks udp packet too short")
	}
	if p[0] != 0 || p[1] != 0 || p[2] != 0 {
		return protocol.Address{}, nil, fmt.Errorf("fragmented socks udp packets are not supported")
	}
	br := bufio.NewReader(bytes.NewReader(p[4:]))
	addr, err := readSocksAddress(br, p[3])
	if err != nil {
		return protocol.Address{}, nil, err
	}
	data, err := io.ReadAll(br)
	if err != nil {
		return protocol.Address{}, nil, err
	}
	return addr, data, nil
}

// buildSocksUDPReply wraps a VLESS datagram back into a SOCKS5 UDP response
// using the tunnel's destination as the reported source address.
func buildSocksUDPReply(target protocol.Address, data []byte) ([]byte, error) {
	out := []byte{0x00, 0x00, 0x00} // RSV, RSV, FRAG
	switch {
	case target.IsDomain():
		if len(target.Domain) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		out = append(out, 0x03, byte(len(target.Domain)))
		out = append(out, target.Domain...)
	case target.IP.To4() != nil:
		out = append(out, 0x01)
		out = append(out, target.IP.To4()...)
	case target.IP.To16() != nil:
		out = append(out, 0x04)
		out = append(out, target.IP.To16()...)
	default:
		return nil, fmt.Errorf("invalid target address")
	}
	out = append(out, byte(target.Port>>8), byte(target.Port))
	return append(out, data...), nil
}
