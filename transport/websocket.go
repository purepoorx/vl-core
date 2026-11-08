package transport

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // required by RFC 6455 handshake
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA

	// Guard against a peer announcing an absurd frame size.
	maxFrameSize   = 16 << 20
	maxMessageSize = 32 << 20

	// Sec-WebSocket-Protocol carries base64url-encoded early data. Bound the
	// decoded size so a hostile handshake cannot pin memory; 8192 bytes is
	// already well above the 2048 that most CDNs are comfortable with.
	maxEarlyData       = 8192
	maxEarlyDataHeader = 12288
)

func wsAcceptKey(key string) string {
	h := sha1.New() //nolint:gosec // required by RFC 6455
	_, _ = io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type wsSettings struct {
	target string // path + any non-ed query, used as the HTTP request target
	path   string // path only, used to validate inbound requests
	ed     int    // client-side early-data limit; 0 disables WS 0-RTT
}

// resolveWSPath accepts both the dedicated "ed" field and Xray's historical
// "path?ed=2048" spelling. The ed parameter is stripped from the request
// target, matching Xray's infra/conf/transport_method.go.
func resolveWSPath(cfg *WSConfig) wsSettings {
	ed := 0
	if cfg != nil {
		ed = cfg.Ed
	}
	p := "/"
	if cfg != nil && cfg.Path != "" {
		p = cfg.Path
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		base, rawQuery := p[:i], p[i+1:]
		if q, err := url.ParseQuery(rawQuery); err == nil {
			if v := q.Get("ed"); v != "" {
				if n, e := strconv.Atoi(v); e == nil && n > 0 {
					ed = n
				}
				q.Del("ed")
				rawQuery = q.Encode()
			}
		}
		if rawQuery != "" {
			p = base + "?" + rawQuery
		} else {
			p = base
		}
	}
	if p == "" {
		p = "/"
	}
	pathOnly := p
	if j := strings.IndexByte(p, '?'); j >= 0 {
		pathOnly = p[:j]
	}
	if ed < 0 {
		ed = 0
	}
	if ed > maxEarlyData {
		ed = maxEarlyData
	}
	return wsSettings{target: p, path: pathOnly, ed: ed}
}

func wsPath(cfg *WSConfig) string {
	return resolveWSPath(cfg).path
}

// ClientHandshake performs the RFC 6455 opening handshake and returns a
// net.Conn over which VLESS bytes can be exchanged as binary messages.
func ClientHandshake(conn net.Conn, cfg *WSConfig, dialAddress string) (net.Conn, error) {
	return ClientHandshakeWithEarlyData(conn, cfg, dialAddress, nil)
}

// ClientHandshakeWithEarlyData is ClientHandshake with WS 0-RTT: earlyData is
// base64url-encoded into Sec-WebSocket-Protocol and travels with the HTTP
// Upgrade request instead of waiting for the 101 response. The caller MUST
// NOT write those bytes again on the returned connection.
func ClientHandshakeWithEarlyData(conn net.Conn, cfg *WSConfig, dialAddress string, earlyData []byte) (net.Conn, error) {
	host := ""
	if cfg != nil && cfg.Host != "" {
		host = cfg.Host
	}
	if host == "" {
		host = dialAddress
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	secKey := base64.StdEncoding.EncodeToString(key[:])
	s := resolveWSPath(cfg)

	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n", s.target, host, secKey)
	if len(earlyData) > 0 {
		fmt.Fprintf(&req, "Sec-WebSocket-Protocol: %s\r\n", base64.RawURLEncoding.EncodeToString(earlyData))
	}
	req.WriteString("\r\n")
	if err := writeAll(conn, []byte(req.String())); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("websocket handshake response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("websocket handshake: server returned %s", resp.Status)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), wsAcceptKey(secKey); got != want {
		return nil, errors.New("websocket handshake: bad Sec-WebSocket-Accept")
	}
	return newWSConn(conn, br, true, nil), nil
}

// ServerHandshake performs the server side of the RFC 6455 opening handshake.
// If the client sent early data in Sec-WebSocket-Protocol (Xray's "?ed=N"),
// it is decoded and prepended to the returned connection's read stream so the
// VLESS inbound sees it as the first bytes of the request.
func ServerHandshake(conn net.Conn, cfg *WSConfig) (net.Conn, error) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("websocket request: %w", err)
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		_ = writeAll(conn, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return nil, errors.New("websocket handshake: not an upgrade request")
	}
	if want := wsPath(cfg); cfg != nil && cfg.Path != "" && req.URL.Path != want {
		_ = writeAll(conn, []byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return nil, fmt.Errorf("websocket handshake: path %q != %q", req.URL.Path, want)
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		_ = writeAll(conn, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return nil, errors.New("websocket handshake: missing Sec-WebSocket-Key")
	}

	proto := req.Header.Get("Sec-WebSocket-Protocol")
	early := decodeEarlyData(proto)

	var resp strings.Builder
	fmt.Fprintf(&resp, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n", wsAcceptKey(key))
	if len(early) > 0 {
		fmt.Fprintf(&resp, "Sec-WebSocket-Protocol: %s\r\n", proto)
	}
	resp.WriteString("\r\n")
	if err := writeAll(conn, []byte(resp.String())); err != nil {
		return nil, err
	}
	return newWSConn(conn, br, false, early), nil
}

var earlyDataReplacer = strings.NewReplacer("+", "-", "/", "_", "=", "")

// decodeEarlyData accepts Xray's base64.RawURLEncoding as well as the older
// V2Ray spelling (standard base64 with padding). Invalid or oversized values
// are ignored, which keeps the connection usable as a plain WebSocket.
func decodeEarlyData(proto string) []byte {
	if proto == "" || len(proto) > maxEarlyDataHeader {
		return nil
	}
	for i := 0; i < len(proto); i++ {
		c := proto[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '+' || c == '/' || c == '=' {
			continue
		}
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(earlyDataReplacer.Replace(proto))
	if err != nil || len(b) == 0 || len(b) > maxEarlyData {
		return nil
	}
	return b
}

type wsConn struct {
	conn      net.Conn
	br        *bufio.Reader
	isClient  bool
	prelude   []byte // early data decoded from Sec-WebSocket-Protocol
	readMu    sync.Mutex
	writeMu   sync.Mutex
	readBuf   []byte
	fragBuf   []byte
	fragOp    byte
	fragments bool
	closeOnce sync.Once
}

func newWSConn(conn net.Conn, br *bufio.Reader, isClient bool, prelude []byte) *wsConn {
	return &wsConn{conn: conn, br: br, isClient: isClient, prelude: prelude}
}

func (c *wsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if len(c.prelude) > 0 {
			n := copy(p, c.prelude)
			c.prelude = c.prelude[n:]
			return n, nil
		}
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		op, payload, err := c.readMessage()
		if err != nil {
			return 0, err
		}
		switch op {
		case wsOpClose:
			return 0, io.EOF
		case wsOpPing:
			_ = c.writeFrame(wsOpPong, payload)
			continue
		case wsOpPong:
			continue
		default:
			c.readBuf = payload
		}
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		_ = c.writeFrame(wsOpClose, nil)
		err = c.conn.Close()
	})
	return err
}

func (c *wsConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *wsConn) readMessage() (byte, []byte, error) {
	for {
		fin, op, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case wsOpText, wsOpBinary:
			if c.fragments {
				return 0, nil, errors.New("websocket: unexpected new message during fragmentation")
			}
			if fin {
				return op, payload, nil
			}
			c.fragments = true
			c.fragOp = op
			c.fragBuf = append(c.fragBuf[:0], payload...)
		case wsOpContinuation:
			if !c.fragments {
				return 0, nil, errors.New("websocket: unexpected continuation frame")
			}
			if len(c.fragBuf)+len(payload) > maxMessageSize {
				return 0, nil, errors.New("websocket: message too large")
			}
			c.fragBuf = append(c.fragBuf, payload...)
			if fin {
				out, firstOp := c.fragBuf, c.fragOp
				c.fragBuf, c.fragOp, c.fragments = nil, 0, false
				return firstOp, out, nil
			}
		case wsOpClose, wsOpPing, wsOpPong:
			if !fin {
				return 0, nil, errors.New("websocket: fragmented control frame")
			}
			return op, payload, nil
		default:
			return 0, nil, fmt.Errorf("websocket: unknown opcode %d", op)
		}
	}
}

func (c *wsConn) readFrame() (bool, byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(c.br, head[:]); err != nil {
		return false, 0, nil, err
	}
	fin := head[0]&0x80 != 0
	op := head[0] & 0x0f
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7f)
	switch length {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(b[:])
		if length&(1<<63) != 0 {
			return false, 0, nil, errors.New("websocket: invalid 64-bit length")
		}
	}
	if length > maxFrameSize {
		return false, 0, nil, errors.New("websocket: frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return false, 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return fin, op, payload, nil
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	return c.writeFrameEx(op, payload, true)
}

func (c *wsConn) writeFrameEx(op byte, payload []byte, fin bool) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var head [14]byte
	head[0] = op
	if fin {
		head[0] |= 0x80
	}
	n := 2
	switch {
	case len(payload) < 126:
		head[1] = byte(len(payload))
	case len(payload) <= 65535:
		head[1] = 126
		binary.BigEndian.PutUint16(head[2:4], uint16(len(payload)))
		n = 4
	default:
		head[1] = 127
		binary.BigEndian.PutUint64(head[2:10], uint64(len(payload)))
		n = 10
	}
	if c.isClient {
		head[1] |= 0x80
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		copy(head[n:n+4], mask[:])
		n += 4
		if err := writeAll(c.conn, head[:n]); err != nil {
			return err
		}
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ mask[i%4]
		}
		return writeAll(c.conn, masked)
	}
	if err := writeAll(c.conn, head[:n]); err != nil {
		return err
	}
	return writeAll(c.conn, payload)
}

type wsListener struct {
	inner net.Listener
	cfg   *WSConfig
}

func newWSListener(inner net.Listener, cfg *WSConfig) net.Listener {
	return &wsListener{inner: inner, cfg: cfg}
}

func (l *wsListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		// Bound the handshake so one slow client cannot stall the accept loop.
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		wc, err := ServerHandshake(conn, l.cfg)
		if err != nil {
			_ = conn.Close()
			continue
		}
		_ = conn.SetDeadline(time.Time{})
		return wc, nil
	}
}

func (l *wsListener) Close() error   { return l.inner.Close() }
func (l *wsListener) Addr() net.Addr { return l.inner.Addr() }

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
