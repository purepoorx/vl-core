package core

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vless-core/protocol"
	"vless-core/transport"
)

const itestUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func testLogger() *Logger { return NewLogger("error", io.Discard) }

func waitAddr(t *testing.T, f func() net.Addr) net.Addr {
	t.Helper()
	for i := 0; i < 400; i++ {
		if a := f(); a != nil {
			return a
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("listener did not start")
	return nil
}

// startPair brings up a VLESS server and a local SOCKS5/HTTP client.
func startPair(t *testing.T, inbound string, srvTr, cliTr *transport.Config) (*Client, *Server) {
	t.Helper()
	srv, err := NewServer(&Config{
		Role:      "server",
		Listen:    "127.0.0.1:0",
		Users:     []UserConfig{{ID: itestUUID, Email: "tester"}},
		Transport: srvTr,
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	srvAddr := waitAddr(t, srv.Addr)

	cli, err := NewClient(&Config{
		Role:    "client",
		Listen:  "127.0.0.1:0",
		Inbound: inbound,
		Server:  &ServerConfig{Address: srvAddr.String(), ID: itestUUID, Transport: cliTr},
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Serve() }()
	waitAddr(t, cli.Addr)
	t.Cleanup(func() { _ = cli.Close(); _ = srv.Close() })
	return cli, srv
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], src)
		}
	}()
	return conn.LocalAddr().String()
}

func socksConnect(t *testing.T, proxy, host string, port uint16) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(conn, greet[:]); err != nil || greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("socks greeting failed: %v %v", greet, err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0x00 {
		conn.Close()
		t.Fatalf("socks CONNECT rejected with rep=0x%02x", head[1])
	}
	var addrLen int
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			t.Fatal(err)
		}
		addrLen = int(n[0])
	default:
		t.Fatalf("bad socks reply atyp %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func httpConnect(t *testing.T, proxy, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if len(line) < 12 || line[9] != '2' {
		t.Fatalf("HTTP CONNECT failed: %q", line)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	return &bufferedConn{Conn: conn, br: br}
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.br.Read(p) }

func echoCheck(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var p uint64
	_, _ = fmt.Sscanf(portStr, "%d", &p)
	return host, uint16(p)
}

func makeSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestEndToEndTCP(t *testing.T) {
	target := startTCPEcho(t)
	host, port := splitHostPort(t, target)
	cli, _ := startPair(t, "socks5", nil, nil)
	conn := socksConnect(t, cli.Addr().String(), host, port)
	defer conn.Close()
	echoCheck(t, conn, "hello-vless-over-raw-tcp")
	echoCheck(t, conn, "second-round-on-the-same-connection")
}

func TestEndToEndHTTPConnect(t *testing.T) {
	target := startTCPEcho(t)
	cli, _ := startPair(t, "http", nil, nil)
	conn := httpConnect(t, cli.Addr().String(), target)
	defer conn.Close()
	echoCheck(t, conn, "hello-vless-over-http-connect")
}

func TestEndToEndTLS(t *testing.T) {
	certFile, keyFile := makeSelfSignedCert(t)
	target := startTCPEcho(t)
	host, port := splitHostPort(t, target)
	cli, _ := startPair(t, "socks5",
		&transport.Config{TLS: &transport.TLSConfig{Enable: true, CertFile: certFile, KeyFile: keyFile}},
		&transport.Config{TLS: &transport.TLSConfig{Enable: true, ServerName: "localhost", InsecureSkipVerify: true}})
	conn := socksConnect(t, cli.Addr().String(), host, port)
	defer conn.Close()
	echoCheck(t, conn, "hello-vless-over-tls")
}

func TestEndToEndWebSocket(t *testing.T) {
	target := startTCPEcho(t)
	host, port := splitHostPort(t, target)
	ws := func() *transport.Config {
		return &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/vless"}}
	}
	cli, _ := startPair(t, "socks5", ws(), ws())
	conn := socksConnect(t, cli.Addr().String(), host, port)
	defer conn.Close()
	echoCheck(t, conn, "hello-vless-over-websocket")
}

func TestEndToEndWebSocketTLS(t *testing.T) {
	certFile, keyFile := makeSelfSignedCert(t)
	target := startTCPEcho(t)
	host, port := splitHostPort(t, target)
	srv := &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray"},
		TLS: &transport.TLSConfig{Enable: true, CertFile: certFile, KeyFile: keyFile}}
	cliTr := &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray"},
		TLS: &transport.TLSConfig{Enable: true, ServerName: "localhost", InsecureSkipVerify: true}}
	cli, _ := startPair(t, "socks5", srv, cliTr)
	conn := socksConnect(t, cli.Addr().String(), host, port)
	defer conn.Close()
	echoCheck(t, conn, "hello-vless-over-wss")
}

func TestEndToEndWebSocketEarlyData(t *testing.T) {
	cases := []struct {
		name         string
		srvWS, cliWS *transport.WSConfig
	}{
		{
			name:  "ed field",
			srvWS: &transport.WSConfig{Path: "/ray"},
			cliWS: &transport.WSConfig{Path: "/ray", Ed: 2048},
		},
		{
			name:  "xray style ed query",
			srvWS: &transport.WSConfig{Path: "/ray?ed=2048"},
			cliWS: &transport.WSConfig{Path: "/ray?ed=2048"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := startTCPEcho(t)
			host, port := splitHostPort(t, target)
			cli, _ := startPair(t, "socks5",
				&transport.Config{Network: "ws", WS: tc.srvWS},
				&transport.Config{Network: "ws", WS: tc.cliWS})
			conn := socksConnect(t, cli.Addr().String(), host, port)
			defer conn.Close()
			echoCheck(t, conn, "hello-vless-over-ws-0rtt")
			echoCheck(t, conn, "second-frame-after-early-header")
		})
	}
}

func TestEndToEndWebSocketEarlyDataUDP(t *testing.T) {
	target := startUDPEcho(t)
	host, port := splitHostPort(t, target)
	cli, _ := startPair(t, "socks5",
		&transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray"}},
		&transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray", Ed: 2048}})
	payload := []byte("udp-over-ws-0rtt")
	got := socksUDPExchange(t, cli.Addr().String(), host, port, payload)
	if string(got) != string(payload) {
		t.Fatalf("udp echo = %x, want %x", got, payload)
	}
}

// socksUDPExchange performs one SOCKS5 UDP ASSOCIATE exchange through proxy
// and returns the datagram payload of the first reply (SOCKS header stripped).
func socksUDPExchange(t *testing.T, proxy, host string, port uint16, payload []byte) []byte {
	t.Helper()
	control, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 greeting, then UDP ASSOCIATE request with 0.0.0.0:0.
	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(control, greet[:]); err != nil || greet[1] != 0 {
		t.Fatalf("socks greeting failed: %v %v", greet, err)
	}
	if _, err := control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(control, head[:]); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0 {
		t.Fatalf("UDP ASSOCIATE rejected: rep=0x%02x", head[1])
	}
	var bindIP []byte
	switch head[3] {
	case 0x01:
		bindIP = make([]byte, 4)
	case 0x04:
		bindIP = make([]byte, 16)
	default:
		t.Fatalf("unexpected bind atyp %d", head[3])
	}
	if _, err := io.ReadFull(control, bindIP); err != nil {
		t.Fatal(err)
	}
	var pb [2]byte
	if _, err := io.ReadFull(control, pb[:]); err != nil {
		t.Fatal(err)
	}
	relay := &net.UDPAddr{IP: net.IP(bindIP), Port: int(binary.BigEndian.Uint16(pb[:]))}

	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(10 * time.Second))

	req := []byte{0x00, 0x00, 0x00}
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(req, 0x01)
		req = append(req, ip...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	req = append(req, payload...)
	if _, err := local.WriteToUDP(req, relay); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, _, err := local.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return parseSocksUDPReply(t, buf[:n])
}

func parseSocksUDPReply(t *testing.T, p []byte) []byte {
	t.Helper()
	if len(p) < 4 || p[0] != 0 || p[1] != 0 || p[2] != 0 {
		t.Fatalf("invalid socks udp reply: %x", p)
	}
	rest := p[4:]
	switch p[3] {
	case 0x01:
		if len(rest) < 6 {
			t.Fatalf("short socks udp reply: %x", p)
		}
		rest = rest[6:]
	case 0x04:
		if len(rest) < 18 {
			t.Fatalf("short socks udp reply: %x", p)
		}
		rest = rest[18:]
	case 0x03:
		if len(rest) < 1 {
			t.Fatalf("short socks udp reply: %x", p)
		}
		n := int(rest[0])
		rest = rest[1+n+2:]
	default:
		t.Fatalf("unknown socks udp atyp %d", p[3])
	}
	return rest
}

func TestEndToEndUDP(t *testing.T) {
	target := startUDPEcho(t)
	host, port := splitHostPort(t, target)
	cli, _ := startPair(t, "socks5", nil, nil)
	payload := []byte("dns-like-udp-payload-\x00\xff")
	got := socksUDPExchange(t, cli.Addr().String(), host, port, payload)
	if string(got) != string(payload) {
		t.Fatalf("udp echo = %x, want %x", got, payload)
	}
}

func TestServerRejectsUnknownUser(t *testing.T) {
	srv, err := NewServer(&Config{
		Role:   "server",
		Listen: "127.0.0.1:0",
		Users:  []UserConfig{{ID: itestUUID}},
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	addr := waitAddr(t, srv.Addr)
	t.Cleanup(func() { _ = srv.Close() })

	// A valid VLESS request header with a different UUID must be rejected.
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	wrong, err := protocol.ParseUUID("00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	// version + wrong uuid + addonsLen + cmd + port + atyp + len + domain
	req := []byte{0x00}
	req = append(req, wrong[:]...)
	req = append(req, 0x00, 0x01, 0x00, 0x50, 0x02, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm')
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	var resp [2]byte
	_, err = io.ReadFull(conn, resp[:])
	if err == nil {
		t.Fatal("server should close the connection for an unknown UUID")
	}
}
