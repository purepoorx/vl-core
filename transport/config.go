// Package transport provides the optional outer transports for VLESS.
// Only the standard library is used: raw TCP, TLS and WebSocket.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

// Config describes the outer transport of a VLESS connection.
type Config struct {
	// Network is "tcp" (default) or "ws".
	Network string     `json:"network,omitempty"`
	TLS     *TLSConfig `json:"tls,omitempty"`
	WS      *WSConfig  `json:"ws,omitempty"`
}

type TLSConfig struct {
	Enable             bool     `json:"enable,omitempty"`
	ServerName         string   `json:"serverName,omitempty"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify,omitempty"`
	CAFile             string   `json:"caFile,omitempty"`
	CertFile           string   `json:"certFile,omitempty"`
	KeyFile            string   `json:"keyFile,omitempty"`
	ALPN               []string `json:"alpn,omitempty"`
}

type WSConfig struct {
	Path string `json:"path,omitempty"` // default "/"
	Host string `json:"host,omitempty"` // default: dial address
}

func (c *Config) orDefault() *Config {
	if c == nil {
		return &Config{Network: "tcp"}
	}
	return c
}

func (c *Config) useWS() bool {
	return c != nil && c.Network == "ws"
}

func (c *Config) useTLS() bool {
	return c != nil && c.TLS != nil && c.TLS.Enable
}

// Dial opens a connection to a VLESS server, applying TLS and/or WebSocket.
func Dial(ctx context.Context, cfg *Config, address string) (net.Conn, error) {
	cfg = cfg.orDefault()
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	if cfg.useTLS() {
		tc, err := clientTLSConfig(cfg.TLS, address)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, tc)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tlsConn
	}

	if cfg.useWS() {
		ws := cfg.WS
		if ws == nil {
			ws = &WSConfig{}
		}
		conn, err = ClientHandshake(conn, ws, address)
		if err != nil {
			return nil, err
		}
	}

	ok = true
	return conn, nil
}

func clientTLSConfig(c *TLSConfig, address string) (*tls.Config, error) {
	serverName := c.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		serverName = host
	}
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // explicit user opt-in
		NextProtos:         c.ALPN,
		MinVersion:         tls.VersionTLS12,
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %q contains no certificates", c.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Listen creates a listener that terminates TLS and/or WebSocket before
// handing VLESS connections to the server.
func Listen(cfg *Config, address string) (net.Listener, error) {
	cfg = cfg.orDefault()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	if cfg.useTLS() {
		if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
			ln.Close()
			return nil, fmt.Errorf("tls requires certFile and keyFile")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   cfg.TLS.ALPN,
			MinVersion:   tls.VersionTLS12,
		}
		ln = tls.NewListener(ln, tlsCfg)
	}
	if cfg.useWS() {
		ws := cfg.WS
		if ws == nil {
			ws = &WSConfig{}
		}
		ln = newWSListener(ln, ws)
	}
	return ln, nil
}
