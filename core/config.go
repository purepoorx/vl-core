package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/purepoorx/vl-core/transport"
)

// Config is the single JSON configuration file for both roles.
//
// Server example:
//
//	{"role":"server","listen":"0.0.0.0:443","users":[{"id":"...","email":"a"}],
//	 "transport":{"network":"tcp","tls":{"enable":true,"certFile":"c.pem","keyFile":"k.pem"}}}
//
// Client example:
//
//	{"role":"client","listen":"127.0.0.1:1080","inbound":"socks5",
//	 "server":{"address":"example.com:443","id":"...","transport":{...}}}
type Config struct {
	Role      string            `json:"role"` // "server" | "client"
	Listen    string            `json:"listen"`
	Users     []UserConfig      `json:"users,omitempty"`
	Inbound   string            `json:"inbound,omitempty"` // client: "socks5" | "http"
	Server    *ServerConfig     `json:"server,omitempty"`
	Transport *transport.Config `json:"transport,omitempty"` // server side
	Timeouts  TimeoutConfig     `json:"timeouts,omitempty"`
	LogLevel  string            `json:"logLevel,omitempty"`
}

type UserConfig struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	Flow  string `json:"flow,omitempty"`
}

type ServerConfig struct {
	Address   string            `json:"address"`
	ID        string            `json:"id"`
	Flow      string            `json:"flow,omitempty"`
	Transport *transport.Config `json:"transport,omitempty"`
}

type TimeoutConfig struct {
	Handshake int `json:"handshake,omitempty"` // seconds, default 15
	Idle      int `json:"idle,omitempty"`      // seconds, 0 = no limit
	UDPIdle   int `json:"udpIdle,omitempty"`   // seconds, default 60
	// HalfClose bounds how long a session may wait after one direction has
	// finished over a transport that cannot signal EOF (WebSocket). The
	// countdown restarts on every byte received, so only a fully silent peer is
	// reaped. Seconds, default 60; a negative value disables the guard.
	HalfClose int `json:"halfClose,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	switch c.Role {
	case "server":
		if c.Listen == "" {
			c.Listen = "0.0.0.0:443"
		}
		if len(c.Users) == 0 {
			return fmt.Errorf("server requires at least one user")
		}
		for i := range c.Users {
			if c.Users[i].ID == "" {
				return fmt.Errorf("users[%d] has no id", i)
			}
			if c.Users[i].Email == "" {
				c.Users[i].Email = fmt.Sprintf("user%d", i)
			}
		}
	case "client":
		if c.Listen == "" {
			c.Listen = "127.0.0.1:1080"
		}
		if c.Inbound == "" {
			c.Inbound = "socks5"
		}
		if c.Inbound != "socks5" && c.Inbound != "http" {
			return fmt.Errorf("unsupported inbound %q (want socks5 or http)", c.Inbound)
		}
		if c.Server == nil || c.Server.Address == "" || c.Server.ID == "" {
			return fmt.Errorf("client requires server.address and server.id")
		}
	default:
		return fmt.Errorf("role must be \"server\" or \"client\", got %q", c.Role)
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return nil
}

func (c *Config) HandshakeTimeout() time.Duration {
	if c.Timeouts.Handshake <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.Timeouts.Handshake) * time.Second
}

func (c *Config) IdleTimeout() time.Duration {
	if c.Timeouts.Idle <= 0 {
		return 0
	}
	return time.Duration(c.Timeouts.Idle) * time.Second
}

func (c *Config) UDPIdleTimeout() time.Duration {
	if c.Timeouts.UDPIdle <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.Timeouts.UDPIdle) * time.Second
}

// HalfCloseTimeout returns how long a session may sit idle after one direction
// finished over a transport that cannot propagate a half-close. Zero means "use
// the default", a negative value disables the guard entirely.
func (c *Config) HalfCloseTimeout() time.Duration {
	switch {
	case c.Timeouts.HalfClose < 0:
		return 0
	case c.Timeouts.HalfClose == 0:
		return 60 * time.Second
	default:
		return time.Duration(c.Timeouts.HalfClose) * time.Second
	}
}
