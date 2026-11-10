package transport

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// wsPair builds a connected client/server websocket pair over a real loopback
// TCP socket (net.Pipe has no buffering, which would deadlock sequential
// Write/Read tests).
func wsPair(t *testing.T, cfg *WSConfig) (*wsConn, *wsConn) {
	return wsPairWithEarlyData(t, cfg, nil)
}

func wsPairWithEarlyData(t *testing.T, cfg *WSConfig, early []byte) (*wsConn, *wsConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverRaw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = clientRaw.SetDeadline(time.Now().Add(10 * time.Second))
	_ = serverRaw.SetDeadline(time.Now().Add(10 * time.Second))

	type result struct {
		c   net.Conn
		err error
	}
	serverCh := make(chan result, 1)
	go func() {
		c, err := ServerHandshake(serverRaw, cfg)
		serverCh <- result{c, err}
	}()
	clientConn, clientErr := ClientHandshakeWithEarlyData(clientRaw, cfg, "example.com:443", early)
	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}
	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	cc := clientConn.(*wsConn)
	sc := sr.c.(*wsConn)
	t.Cleanup(func() { _ = cc.Close(); _ = sc.Close() })
	return cc, sc
}

func TestWebSocketRoundTrip(t *testing.T) {
	client, server := wsPair(t, &WSConfig{Path: "/vless"})

	for _, msg := range []string{"hello", string(bytes.Repeat([]byte{0x00, 0xff, 0x41}, 1000)), "tail"} {
		if _, err := client.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != msg {
			t.Fatalf("server received %q, want %q", got[:20], msg[:20])
		}
		// and the other direction (server frames are unmasked)
		if _, err := server.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != msg {
			t.Fatalf("client received %q, want %q", got[:20], msg[:20])
		}
	}
}

func TestWebSocketLargePayloadAndPartialRead(t *testing.T) {
	client, server := wsPair(t, nil)
	payload := bytes.Repeat([]byte("VLESS"), 5000) // 25 KB, needs 16-bit length
	go func() { _, _ = client.Write(payload) }()

	// Read in small chunks to exercise the leftover-payload path.
	got := make([]byte, 0, len(payload))
	buf := make([]byte, 7)
	for len(got) < len(payload) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
		if n == 0 {
			t.Fatal("zero-length read")
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("large payload mismatch")
	}
}

func TestWebSocketFragmentationAndControlFrames(t *testing.T) {
	client, server := wsPair(t, nil)

	// Manually send a fragmented binary message from the client.
	if err := client.writeFrameEx(wsOpBinary, []byte("frag-"), false); err != nil {
		t.Fatal(err)
	}
	if err := client.writeFrameEx(wsOpContinuation, []byte("ment"), true); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "frag-ment" {
		t.Fatalf("fragmented message = %q", got)
	}

	// A ping must be answered with a pong and not surface to the reader.
	if err := client.writeFrame(wsOpPing, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := client.writeFrame(wsOpBinary, []byte("data")); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, 4)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("after ping = %q", got)
	}
	// wsConn.Read swallows PONG frames by design, so inspect the raw frame.
	_, op, pong, err := client.readFrame()
	if err != nil {
		t.Fatalf("expected pong on client: %v", err)
	}
	if op != wsOpPong || string(pong) != "ping" {
		t.Fatalf("pong frame = op %d payload %q", op, pong)
	}
}

func TestWebSocketClientFramesAreMasked(t *testing.T) {
	client, server := wsPair(t, nil)
	if !client.isClient || server.isClient {
		t.Fatal("unexpected role flags")
	}
	if err := client.writeFrame(wsOpBinary, []byte("x")); err != nil {
		t.Fatal(err)
	}
	_, op, payload, err := server.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if op != wsOpBinary || string(payload) != "x" {
		t.Fatalf("frame = op %d payload %q", op, payload)
	}
}

// writeRawFrame injects bytes the encoder would never produce, so the framing
// rules can be tested against a hostile peer.
func writeRawFrame(t *testing.T, conn net.Conn, b0 byte, rest ...[]byte) {
	t.Helper()
	buf := []byte{b0}
	for _, p := range rest {
		buf = append(buf, p...)
	}
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
}

// writeMaskedFrame sends a correctly masked short frame from the client role.
func writeMaskedFrame(t *testing.T, conn net.Conn, op byte, payload []byte) {
	t.Helper()
	if len(payload) > 125 {
		t.Fatalf("writeMaskedFrame only supports short frames, got %d", len(payload))
	}
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	buf := []byte{0x80 | op, 0x80 | byte(len(payload))}
	buf = append(buf, mask[:]...)
	for i := range payload {
		buf = append(buf, payload[i]^mask[i%4])
	}
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketRejectsOversizedControlFrame(t *testing.T) {
	client, server := wsPair(t, nil)
	// FIN + ping with the 7-bit length set to 126: a control frame must never
	// use the extended length form (RFC 6455 §5.5). Only the header is needed,
	// because the reader must reject it before consuming a payload.
	writeRawFrame(t, client.conn, 0x89, []byte{126})
	if _, err := server.Read(make([]byte, 16)); err == nil {
		t.Fatal("server accepted a control frame longer than 125 bytes")
	}
}

func TestWebSocketRejectsFragmentedControlFrame(t *testing.T) {
	client, server := wsPair(t, nil)
	// Missing FIN on a ping.
	writeRawFrame(t, client.conn, 0x09, []byte{0x81, 0, 0, 0, 0})
	if _, err := server.Read(make([]byte, 16)); err == nil {
		t.Fatal("server accepted a fragmented control frame")
	}
}

func TestWebSocketRejectsUnmaskedClientFrame(t *testing.T) {
	client, server := wsPair(t, nil)
	// FIN + binary, length 1, no MASK bit, payload "x".
	writeRawFrame(t, client.conn, 0x82, []byte{0x01, 'x'})
	if _, err := server.Read(make([]byte, 16)); err == nil {
		t.Fatal("server accepted an unmasked client frame")
	}
}

func TestWebSocketRejectsReservedBits(t *testing.T) {
	client, server := wsPair(t, nil)
	// FIN + RSV1 + binary, masked, length 1.
	writeRawFrame(t, client.conn, 0xc2, []byte{0x81, 1, 2, 3, 4, 'x' ^ 1})
	if _, err := server.Read(make([]byte, 16)); err == nil {
		t.Fatal("server accepted a frame with RSV1 set")
	}
}

func TestWebSocketRejectsBadClosePayloads(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"single byte", []byte{0x03}},
		{"reserved code 1005", []byte{0x03, 0xed}},
		{"reserved code 1006", []byte{0x03, 0xee}},
		{"out of range 2999", []byte{0x0b, 0xb7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := wsPair(t, nil)
			writeMaskedFrame(t, client.conn, wsOpClose, tc.payload)
			if _, err := server.Read(make([]byte, 16)); err == nil {
				t.Fatalf("server accepted close payload %x", tc.payload)
			}
		})
	}
}

func TestWebSocketAcceptsValidCloseFrame(t *testing.T) {
	client, server := wsPair(t, nil)
	writeMaskedFrame(t, client.conn, wsOpClose, []byte{0x03, 0xe8, 'b', 'y', 'e'}) // 1000 + reason
	if _, err := server.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("Read after close = %v, want io.EOF", err)
	}
}

func TestValidateClosePayload(t *testing.T) {
	ok := [][]byte{
		nil,
		{0x03, 0xe8},           // 1000
		{0x03, 0xf3},           // 1011
		{0x0b, 0xb8},           // 3000
		{0x13, 0x87},           // 4999
		{0x03, 0xe8, 'o', 'k'}, // 1000 with reason
	}
	for _, p := range ok {
		if err := validateClosePayload(p); err != nil {
			t.Fatalf("validateClosePayload(%x) = %v, want nil", p, err)
		}
	}
	bad := [][]byte{
		{0x03},
		{0x03, 0xed}, // 1005
		{0x03, 0xee}, // 1006
		{0x03, 0xf7}, // 1015
		{0x00, 0x00}, // 0
		{0x0b, 0xb7}, // 2999
	}
	for _, p := range bad {
		if err := validateClosePayload(p); err == nil {
			t.Fatalf("validateClosePayload(%x) = nil, want error", p)
		}
	}
}

func TestWebSocketAcceptsMaxSizeControlFrame(t *testing.T) {
	client, server := wsPair(t, nil)
	writeMaskedFrame(t, client.conn, wsOpPing, bytes.Repeat([]byte("p"), 125))
	if _, err := client.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 11)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ping of exactly 125 bytes was rejected: %v", err)
	}
	if string(got) != "still-alive" {
		t.Fatalf("after max ping = %q", got)
	}
}

func TestResolveWSPath(t *testing.T) {
	cases := []struct {
		name         string
		cfg          *WSConfig
		target, path string
		ed           int
	}{
		{"default", nil, "/", "/", 0},
		{"relative path", &WSConfig{Path: "ray"}, "/ray", "/ray", 0},
		{"ed field", &WSConfig{Path: "/ray", Ed: 2048}, "/ray", "/ray", 2048},
		{"ed query", &WSConfig{Path: "/ray?ed=2048"}, "/ray", "/ray", 2048},
		{"ed query with params", &WSConfig{Path: "/ray?ed=1024&foo=bar"}, "/ray?foo=bar", "/ray", 1024},
		{"clamped", &WSConfig{Path: "/ray", Ed: 1 << 30}, "/ray", "/ray", maxEarlyData},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveWSPath(tc.cfg)
			if got.target != tc.target || got.path != tc.path || got.ed != tc.ed {
				t.Fatalf("resolveWSPath = %+v, want target=%q path=%q ed=%d", got, tc.target, tc.path, tc.ed)
			}
		})
	}
}

func TestDecodeEarlyData(t *testing.T) {
	raw := []byte("VLESS header bytes!")
	if got := decodeEarlyData(base64.RawURLEncoding.EncodeToString(raw)); !bytes.Equal(got, raw) {
		t.Fatalf("rawurl early data = %q", got)
	}
	// Older V2Ray clients use standard base64 with + / and padding.
	weird := []byte{0xfb, 0xff, 0xbf, 0x01, 0x00}
	if got := decodeEarlyData(base64.StdEncoding.EncodeToString(weird)); !bytes.Equal(got, weird) {
		t.Fatalf("std base64 early data = %x, want %x", got, weird)
	}
	for _, bad := range []string{
		"", "not!base64", "%%%",
		string(bytes.Repeat([]byte("A"), maxEarlyDataHeader+1)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("x"), maxEarlyData+1)),
	} {
		if got := decodeEarlyData(bad); got != nil {
			t.Fatalf("decodeEarlyData(len=%d) = %d bytes, want nil", len(bad), len(got))
		}
	}
}

func TestWebSocketEarlyDataPrelude(t *testing.T) {
	cfg := &WSConfig{Path: "/ray", Ed: 2048}
	early := []byte("VLESS request header plus first payload")
	client, server := wsPairWithEarlyData(t, cfg, early)

	got := make([]byte, len(early))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, early) {
		t.Fatalf("early data = %q, want %q", got, early)
	}

	// After the prelude is drained, ordinary frames work in both directions.
	if _, err := client.Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "frame" {
		t.Fatalf("after early data, frame = %q", buf)
	}
	if _, err := server.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "reply" {
		t.Fatalf("downlink = %q", buf)
	}
}

func TestWebSocketServerEarlyDataEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	serverRaw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = clientRaw.SetDeadline(time.Now().Add(10 * time.Second))
	_ = serverRaw.SetDeadline(time.Now().Add(10 * time.Second))

	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ServerHandshake(serverRaw, &WSConfig{Path: "/ray"})
		ch <- result{c, err}
	}()

	early := []byte{0xfb, 0xff, 0xbf, 0x01, 0x00}
	proto := base64.StdEncoding.EncodeToString(early)
	fmt.Fprintf(clientRaw, "GET /ray HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\n\r\n", proto)

	resp, err := http.ReadResponse(bufio.NewReader(clientRaw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %s", resp.Status)
	}
	if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != proto {
		t.Fatalf("echoed subprotocol = %q, want %q", got, proto)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("server handshake: %v", r.err)
	}
	defer r.c.Close()
	got := make([]byte, len(early))
	if _, err := io.ReadFull(r.c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, early) {
		t.Fatalf("prelude = %x, want %x", got, early)
	}
}

// TestClientHandshakeSendsEarlyDataHeader inspects the actual bytes on the
// wire, so a regression that silently falls back to a normal handshake
// cannot make the end-to-end 0-RTT tests pass falsely.
func TestClientHandshakeSendsEarlyDataHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	captured := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			captured <- ""
			return
		}
		captured <- req.Header.Get("Sec-WebSocket-Protocol")
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	early := []byte("VLESS request header bytes")
	// The handshake intentionally fails (400); only the request bytes matter.
	_, _ = ClientHandshakeWithEarlyData(raw, &WSConfig{Path: "/ray?ed=2048"}, "example.com:443", early)

	proto := <-captured
	want := base64.RawURLEncoding.EncodeToString(early)
	if proto != want {
		t.Fatalf("Sec-WebSocket-Protocol = %q, want %q", proto, want)
	}
}
