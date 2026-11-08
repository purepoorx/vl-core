package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// wsPair builds a connected client/server websocket pair over a real loopback
// TCP socket (net.Pipe has no buffering, which would deadlock sequential
// Write/Read tests).
func wsPair(t *testing.T, cfg *WSConfig) (*wsConn, *wsConn) {
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
	clientConn, clientErr := ClientHandshake(clientRaw, cfg, "example.com:443")
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
