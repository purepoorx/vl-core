package core

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"vless-core/transport"
)

const (
	xrayStreamTCP  = `{"network":"tcp","security":"none"}`
	xrayStreamWS   = `{"network":"ws","wsSettings":{"path":"/ray"}}`
	xrayStreamWSED = `{"network":"ws","wsSettings":{"path":"/ray?ed=2048"}}`
)

// These tests cross-check the wire format against the real Xray-core binary.
// They only run when VL_CORE_XRAY_BIN points to an official xray executable:
//
//	VL_CORE_XRAY_BIN=/path/to/xray go test ./core -run TestInterop -v
//
// See examples/xray-server.json and examples/xray-client.json for the
// equivalent standalone configuration files.

const xrayServerConfig = `{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1", "port": %d, "protocol": "vless", "tag": "vless-in",
    "settings": {
      "clients": [{"id": "%s", "email": "alice", "flow": ""}],
      "decryption": "none"
    },
    "streamSettings": %s
  }],
  "outbounds": [{
    "protocol": "freedom", "tag": "direct",
    "settings": {"finalRules": [{"action": "Allow"}]}
  }]
}`

const xrayClientConfig = `{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1", "port": %d, "protocol": "socks", "tag": "socks-in",
    "settings": {"auth": "noauth", "udp": true}
  }],
  "outbounds": [{
    "protocol": "vless", "tag": "vless-out",
    "settings": {"vnext": [{
      "address": "127.0.0.1", "port": %d,
      "users": [{"id": "%s", "encryption": "none", "flow": ""}]
    }]},
    "streamSettings": %s
  }]
}`

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never became reachable", addr)
}

func startXray(t *testing.T, bin, config string, extraEnv ...string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
}

func TestInteropWithOfficialXray(t *testing.T) {
	bin := os.Getenv("VL_CORE_XRAY_BIN")
	if bin == "" {
		t.Skip("set VL_CORE_XRAY_BIN to an official xray binary to run interop tests")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("xray binary %q: %v", bin, err)
	}

	t.Run("xray-server-vlcore-client", func(t *testing.T) {
		target := startTCPEcho(t)
		host, port := splitHostPort(t, target)
		xrayPort := freePort(t)
		startXray(t, bin, fmt.Sprintf(xrayServerConfig, xrayPort, itestUUID, xrayStreamTCP))
		xrayAddr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
		waitTCP(t, xrayAddr)

		cli, err := NewClient(&Config{
			Role:    "client",
			Listen:  "127.0.0.1:0",
			Inbound: "socks5",
			Server:  &ServerConfig{Address: xrayAddr, ID: itestUUID},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = cli.Serve() }()
		waitAddr(t, cli.Addr)
		t.Cleanup(func() { _ = cli.Close() })

		conn := socksConnect(t, cli.Addr().String(), host, port)
		defer conn.Close()
		echoCheck(t, conn, "vl-core client -> official Xray server")
	})

	t.Run("xray-server-vlcore-client-udp", func(t *testing.T) {
		target := startUDPEcho(t)
		host, port := splitHostPort(t, target)
		xrayPort := freePort(t)
		startXray(t, bin, fmt.Sprintf(xrayServerConfig, xrayPort, itestUUID, xrayStreamTCP))
		xrayAddr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
		waitTCP(t, xrayAddr)

		cli, err := NewClient(&Config{
			Role:    "client",
			Listen:  "127.0.0.1:0",
			Inbound: "socks5",
			Server:  &ServerConfig{Address: xrayAddr, ID: itestUUID},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = cli.Serve() }()
		waitAddr(t, cli.Addr)
		t.Cleanup(func() { _ = cli.Close() })

		payload := []byte("vl-core-udp -> official Xray server")
		got := socksUDPExchange(t, cli.Addr().String(), host, port, payload)
		if string(got) != string(payload) {
			t.Fatalf("udp echo = %q, want %q", got, payload)
		}
	})

	t.Run("vlcore-server-xray-client", func(t *testing.T) {
		target := startTCPEcho(t)
		host, port := splitHostPort(t, target)

		srv, err := NewServer(&Config{
			Role:   "server",
			Listen: "127.0.0.1:0",
			Users:  []UserConfig{{ID: itestUUID, Email: "alice"}},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve() }()
		_, vlessPort := splitHostPort(t, waitAddr(t, srv.Addr).String())
		t.Cleanup(func() { _ = srv.Close() })

		socksPort := freePort(t)
		startXray(t, bin, fmt.Sprintf(xrayClientConfig, socksPort, int(vlessPort), itestUUID, xrayStreamTCP))
		socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
		waitTCP(t, socksAddr)

		conn := socksConnect(t, socksAddr, host, port)
		defer conn.Close()
		echoCheck(t, conn, "official Xray client -> vl-core server")
	})

	t.Run("vlcore-server-xray-client-udp", func(t *testing.T) {
		target := startUDPEcho(t)
		host, port := splitHostPort(t, target)

		srv, err := NewServer(&Config{
			Role:   "server",
			Listen: "127.0.0.1:0",
			Users:  []UserConfig{{ID: itestUUID, Email: "alice"}},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve() }()
		_, vlessPort := splitHostPort(t, waitAddr(t, srv.Addr).String())
		t.Cleanup(func() { _ = srv.Close() })

		socksPort := freePort(t)
		// Xray 26.x enables "cone" by default, which turns non-53/443 UDP into
		// XUDP over Mux - an extension this minimal core does not implement.
		// Disable it so both sides speak plain VLESS UDP (CommandUDP).
		startXray(t, bin, fmt.Sprintf(xrayClientConfig, socksPort, int(vlessPort), itestUUID, xrayStreamTCP),
			"XRAY_CONE_DISABLED=true")
		socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
		waitTCP(t, socksAddr)

		payload := []byte("official Xray udp -> vl-core server")
		got := socksUDPExchange(t, socksAddr, host, port, payload)
		if string(got) != string(payload) {
			t.Fatalf("udp echo = %q, want %q", got, payload)
		}
	})

	// The WebSocket implementation here is written from scratch against
	// RFC 6455; these two cases prove it interoperates with Xray's
	// gorilla/websocket based transport in both directions.
	t.Run("xray-server-ws-vlcore-client", func(t *testing.T) {
		target := startTCPEcho(t)
		host, port := splitHostPort(t, target)
		xrayPort := freePort(t)
		startXray(t, bin, fmt.Sprintf(xrayServerConfig, xrayPort, itestUUID, xrayStreamWS))
		xrayAddr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
		waitTCP(t, xrayAddr)

		cli, err := NewClient(&Config{
			Role:    "client",
			Listen:  "127.0.0.1:0",
			Inbound: "socks5",
			Server: &ServerConfig{
				Address:   xrayAddr,
				ID:        itestUUID,
				Transport: &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray"}},
			},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = cli.Serve() }()
		waitAddr(t, cli.Addr)
		t.Cleanup(func() { _ = cli.Close() })

		conn := socksConnect(t, cli.Addr().String(), host, port)
		defer conn.Close()
		echoCheck(t, conn, "vl-core WS client -> official Xray WS server")
	})

	t.Run("vlcore-server-ws-xray-client", func(t *testing.T) {
		target := startTCPEcho(t)
		host, port := splitHostPort(t, target)

		srv, err := NewServer(&Config{
			Role:      "server",
			Listen:    "127.0.0.1:0",
			Users:     []UserConfig{{ID: itestUUID, Email: "alice"}},
			Transport: &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray"}},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve() }()
		_, vlessPort := splitHostPort(t, waitAddr(t, srv.Addr).String())
		t.Cleanup(func() { _ = srv.Close() })

		socksPort := freePort(t)
		startXray(t, bin, fmt.Sprintf(xrayClientConfig, socksPort, int(vlessPort), itestUUID, xrayStreamWS))
		socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
		waitTCP(t, socksAddr)

		conn := socksConnect(t, socksAddr, host, port)
		defer conn.Close()
		echoCheck(t, conn, "official Xray WS client -> vl-core WS server")
	})

	// WS 0-RTT: Xray's "?ed=2048" puts the first upstream bytes into
	// Sec-WebSocket-Protocol. Both directions are checked here.
	t.Run("vlcore-server-ws-xray-client-0rtt", func(t *testing.T) {
		target := startTCPEcho(t)
		host, port := splitHostPort(t, target)

		srv, err := NewServer(&Config{
			Role:      "server",
			Listen:    "127.0.0.1:0",
			Users:     []UserConfig{{ID: itestUUID, Email: "alice"}},
			Transport: &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray"}},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve() }()
		_, vlessPort := splitHostPort(t, waitAddr(t, srv.Addr).String())
		t.Cleanup(func() { _ = srv.Close() })

		socksPort := freePort(t)
		startXray(t, bin, fmt.Sprintf(xrayClientConfig, socksPort, int(vlessPort), itestUUID, xrayStreamWSED))
		socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
		waitTCP(t, socksAddr)

		conn := socksConnect(t, socksAddr, host, port)
		defer conn.Close()
		echoCheck(t, conn, "official Xray WS 0-RTT client -> vl-core WS server")
	})

	t.Run("xray-server-ws-vlcore-client-0rtt", func(t *testing.T) {
		target := startTCPEcho(t)
		host, port := splitHostPort(t, target)
		xrayPort := freePort(t)
		startXray(t, bin, fmt.Sprintf(xrayServerConfig, xrayPort, itestUUID, xrayStreamWS))
		xrayAddr := fmt.Sprintf("127.0.0.1:%d", xrayPort)
		waitTCP(t, xrayAddr)

		cli, err := NewClient(&Config{
			Role:    "client",
			Listen:  "127.0.0.1:0",
			Inbound: "socks5",
			Server: &ServerConfig{
				Address:   xrayAddr,
				ID:        itestUUID,
				Transport: &transport.Config{Network: "ws", WS: &transport.WSConfig{Path: "/ray", Ed: 2048}},
			},
		}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = cli.Serve() }()
		waitAddr(t, cli.Addr)
		t.Cleanup(func() { _ = cli.Close() })

		conn := socksConnect(t, cli.Addr().String(), host, port)
		defer conn.Close()
		echoCheck(t, conn, "vl-core WS 0-RTT client -> official Xray WS server")
	})
}
