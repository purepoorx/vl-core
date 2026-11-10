package core

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/purepoorx/vl-core/protocol"
	"github.com/purepoorx/vl-core/transport"
)

// Client is a local proxy that accepts SOCKS5/HTTP CONNECT and tunnels the
// traffic through a VLESS server.
type Client struct {
	cfg       *Config
	log       *Logger
	uuid      protocol.UUID
	flow      string
	server    string
	transport *transport.Config

	mu         sync.Mutex
	tcpLn      net.Listener
	conns      map[net.Conn]struct{}
	associates map[*udpAssociate]struct{}
	closed     bool
}

// vlessConn is an established VLESS connection. The response header is read
// lazily by the downlink goroutine: some servers only flush it together with
// the first downstream payload, so the uplink must not wait for it.
type vlessConn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
}

func (v *vlessConn) Close() error { return v.conn.Close() }

func NewClient(cfg *Config, log *Logger) (*Client, error) {
	if cfg.Role != "client" {
		return nil, fmt.Errorf("config role is %q, want client", cfg.Role)
	}
	id, err := protocol.ParseUUID(cfg.Server.ID)
	if err != nil {
		return nil, fmt.Errorf("server.id: %w", err)
	}
	flow := cfg.Server.Flow
	if flow == "none" {
		flow = ""
	}
	if flow != "" {
		log.Warn("flow %q will be encoded in the header, but this core does not implement the XTLS Vision data plane", flow)
	}
	return &Client{
		cfg:        cfg,
		log:        log,
		uuid:       id,
		flow:       flow,
		server:     cfg.Server.Address,
		transport:  cfg.Server.Transport,
		conns:      make(map[net.Conn]struct{}),
		associates: make(map[*udpAssociate]struct{}),
	}, nil
}

// Addr returns the actual local listening address.
func (c *Client) Addr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tcpLn == nil {
		return nil
	}
	return c.tcpLn.Addr()
}

// Serve accepts local proxy connections and blocks until Close is called.
func (c *Client) Serve() error {
	tcpLn, err := net.Listen("tcp", c.cfg.Listen)
	if err != nil {
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		tcpLn.Close()
		return nil
	}
	c.tcpLn = tcpLn
	c.mu.Unlock()

	c.log.Info("VLESS client listening on %s (inbound=%s, server=%s)", tcpLn.Addr(), c.cfg.Inbound, c.server)
	for {
		conn, err := tcpLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || c.isClosed() {
				return nil
			}
			c.log.Warn("accept: %v", err)
			continue
		}
		c.track(conn, true)
		go func() {
			defer c.track(conn, false)
			if c.cfg.Inbound == "http" {
				c.handleHTTP(conn)
			} else {
				c.handleSocks5(conn)
			}
		}()
	}
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) track(conn net.Conn, add bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if add {
		c.conns[conn] = struct{}{}
		return
	}
	delete(c.conns, conn)
	_ = conn.Close()
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	tcpLn := c.tcpLn
	conns := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	assocs := make([]*udpAssociate, 0, len(c.associates))
	for a := range c.associates {
		assocs = append(assocs, a)
	}
	c.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
	for _, a := range assocs {
		a.close()
	}
	if tcpLn != nil {
		return tcpLn.Close()
	}
	return nil
}

// openVLESS connects to the configured VLESS server and writes the request
// header. It does not wait for the response header (see relayTCP).
//
// Over WebSocket with an early-data limit configured, the request header is
// sent inside the opening handshake (WS 0-RTT) instead of a separate frame.
func (c *Client) openVLESS(ctx context.Context, target protocol.Address, command protocol.Command) (*vlessConn, error) {
	h := &protocol.RequestHeader{
		Version: protocol.Version,
		UUID:    c.uuid,
		Addons:  &protocol.Addons{Flow: c.flow},
		Command: command,
		Address: target,
	}
	var header bytes.Buffer
	if err := protocol.WriteRequestHeader(&header, h); err != nil {
		return nil, err
	}

	conn, usedEarly, err := transport.DialWithEarlyData(ctx, c.transport, c.server, header.Bytes())
	if err != nil {
		return nil, err
	}
	vc := &vlessConn{conn: conn, br: bufio.NewReader(conn), bw: bufio.NewWriter(conn)}
	if d := c.cfg.HandshakeTimeout(); d > 0 {
		_ = conn.SetDeadline(time.Now().Add(d))
	}
	if !usedEarly {
		if _, err := vc.bw.Write(header.Bytes()); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if err := vc.bw.Flush(); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if d := c.cfg.IdleTimeout(); d > 0 {
		_ = conn.SetDeadline(time.Now().Add(d))
	} else {
		_ = conn.SetDeadline(time.Time{})
	}
	return vc, nil
}

// relayTCP connects a local inbound stream to a VLESS TCP connection.
func (c *Client) relayTCP(local net.Conn, localR io.Reader, vc *vlessConn) error {
	errCh := make(chan error, 2)
	go func() {
		err := copyAndFlush(vc.bw, localR)
		tryCloseWrite(vc.conn)
		errCh <- err
	}()
	go func() {
		if _, err := protocol.ReadResponseHeader(vc.br, protocol.Version); err != nil {
			// Fatal (bad UUID, wrong server, ...): unblock the uplink too.
			_ = vc.conn.Close()
			_ = local.Close()
			errCh <- err
			return
		}
		_, err := io.Copy(local, vc.br)
		tryCloseWrite(local)
		errCh <- err
	}()
	first, second := <-errCh, <-errCh
	if first != nil && first != io.EOF {
		return first
	}
	if second != nil && second != io.EOF {
		return second
	}
	return nil
}
