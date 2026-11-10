package core

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/purepoorx/vl-core/transport"
)

// startEOFReplyServer accepts connections, reads until FIN, then replies
// "done" and closes. This is the minimal FTP-style protocol: the reply only
// exists because the peer signalled end-of-stream.
func startEOFReplyServer(t *testing.T) string {
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
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						break
					}
				}
				_, _ = conn.Write([]byte("done"))
			}()
		}
	}()
	return ln.Addr().String()
}

func wsTransport() *transport.Config {
	return &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray"}}
}

// TestTCPHalfClosePropagates is the control case: raw TCP has a real
// CloseWrite, so a FIN-terminated protocol must still complete.
func TestTCPHalfClosePropagates(t *testing.T) {
	target := startEOFReplyServer(t)
	host, port := splitHostPort(t, target)
	cli, _ := startPair(t, "socks5", nil, nil)

	conn := socksConnect(t, cli.Addr().String(), host, port)
	defer conn.Close()
	if _, err := conn.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("underlying conn is not *net.TCPConn")
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading reply after half-close: %v", err)
	}
	if string(got) != "done" {
		t.Fatalf("reply = %q, want %q", got, "done")
	}
}

// TestWebSocketHalfCloseIsBounded covers the WebSocket limitation: RFC 6455 has
// no half-close, so the reply can never arrive. What must not happen is the
// session hanging forever, so halfClose must reap it.
func TestWebSocketHalfCloseIsBounded(t *testing.T) {
	target := startEOFReplyServer(t)
	host, port := splitHostPort(t, target)
	cli, _ := startPairTimeout(t, "socks5", wsTransport(), wsTransport(), TimeoutConfig{HalfClose: 1})

	conn := socksConnect(t, cli.Addr().String(), host, port)
	defer conn.Close()
	if _, err := conn.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("underlying conn is not *net.TCPConn")
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got, err := io.ReadAll(conn)
	elapsed := time.Since(start)

	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("idle WS session was not reaped after halfClose elapsed (%s)", elapsed.Round(time.Millisecond))
	}
	if err != nil {
		t.Fatalf("read after bounded wait: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("WebSocket should not deliver a FIN-triggered reply, got %q", got)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("session was reaped after %s, before halfClose could elapse", elapsed.Round(time.Millisecond))
	}
	if elapsed > 4*time.Second {
		t.Fatalf("session took %s to reap with halfClose=1s", elapsed.Round(time.Millisecond))
	}
}

// TestHalfCloseGuardPostponedByTraffic proves the guard only reaps a silent
// peer: traffic on the surviving direction keeps pushing the deadline back.
func TestHalfCloseGuardPostponedByTraffic(t *testing.T) {
	guardSide, peerSide := net.Pipe()
	defer guardSide.Close()
	defer peerSide.Close()

	guard := newHalfCloseGuard(guardSide, 150*time.Millisecond)
	guard.arm()

	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		if _, err := peerSide.Read(buf); err != nil {
			close(closed)
		}
	}()

	for i := 0; i < 4; i++ {
		time.Sleep(100 * time.Millisecond)
		guard.touch()
		select {
		case <-closed:
			t.Fatal("guard closed the connection while traffic was still flowing")
		default:
		}
	}

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("guard never closed the connection after traffic stopped")
	}
	guard.stop()
}

func TestHalfCloseTimeoutConfig(t *testing.T) {
	cases := []struct {
		in   int
		want time.Duration
	}{
		{0, 60 * time.Second}, // unset -> default
		{30, 30 * time.Second},
		{-1, 0}, // disabled
	}
	for _, tc := range cases {
		cfg := &Config{Timeouts: TimeoutConfig{HalfClose: tc.in}}
		if got := cfg.HalfCloseTimeout(); got != tc.want {
			t.Fatalf("HalfCloseTimeout(%d) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
