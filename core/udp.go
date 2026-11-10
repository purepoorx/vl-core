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

	"github.com/purepoorx/vl-core/protocol"
)

// udpAssociate represents one SOCKS5 UDP ASSOCIATE session.
//
// RFC 1928 ties an association to its control TCP connection, not to the client
// IP. Each association therefore owns a dedicated relay socket with its own
// advertised port, and is pinned to the first client address that sends a valid
// datagram. Two clients on the same host can no longer read each other's
// replies, which a shared socket keyed by client IP allowed.
//
// Each distinct destination gets its own VLESS UDP connection (tunnel).
type udpAssociate struct {
	client     *Client
	relay      *net.UDPConn
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

// listenRelaySocket binds a dedicated UDP socket for a single association.
// It reuses the local IP of the control connection so the advertised address
// is reachable by the client, and lets the kernel choose an ephemeral port.
func listenRelaySocket(local net.Conn) (*net.UDPConn, error) {
	ip := net.IPv4(127, 0, 0, 1)
	if ta, ok := local.LocalAddr().(*net.TCPAddr); ok && ta.IP != nil {
		ip = ta.IP
	}
	return net.ListenUDP("udp", &net.UDPAddr{IP: ip})
}

func (c *Client) newAssociate(relay *net.UDPConn) *udpAssociate {
	a := &udpAssociate{
		client:  c,
		relay:   relay,
		tunnels: make(map[string]*udpTunnel),
		done:    make(chan struct{}),
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		a.close()
		return nil
	}
	c.associates[a] = struct{}{}
	c.mu.Unlock()
	go a.serveRelay()
	go a.reapLoop()
	return a
}

func (c *Client) removeAssociate(a *udpAssociate) {
	c.mu.Lock()
	delete(c.associates, a)
	c.mu.Unlock()
	a.close()
}

// serveRelay reads datagrams addressed to this association's relay port.
func (a *udpAssociate) serveRelay() {
	buf := make([]byte, 65535)
	for {
		n, src, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		go a.handlePacket(src, pkt)
	}
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
		if a.relay != nil {
			_ = a.relay.Close()
		}
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
		if _, err := a.relay.WriteToUDP(reply, src); err != nil {
			return
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

// handlePacket validates one datagram received on the association's relay port.
// The first valid sender becomes the association's client address; datagrams
// from any other source are dropped so a stray or spoofed packet cannot inject
// traffic into the session.
func (a *udpAssociate) handlePacket(src *net.UDPAddr, p []byte) {
	addr, data, err := parseSocksUDPPayload(p)
	if err != nil {
		a.client.log.Debug("bad socks udp packet from %s: %v", src, err)
		return
	}

	a.mu.Lock()
	if a.clientAddr == nil {
		bound := *src
		a.clientAddr = &bound
	}
	bound := a.clientAddr
	a.mu.Unlock()
	if !sameUDPAddr(bound, src) {
		a.client.log.Debug("socks udp packet from unexpected source %s (bound to %s)", src, bound)
		return
	}
	if len(data) == 0 {
		return
	}

	t, err := a.getTunnel(addr)
	if err != nil {
		a.client.log.Warn("udp tunnel to %s failed: %v", addr.String(), err)
		return
	}
	if err := t.writePacket(data); err != nil {
		a.client.log.Debug("udp write %s: %v", addr.String(), err)
	}
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
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
