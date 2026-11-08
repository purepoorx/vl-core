package core

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"vless-core/protocol"
	"vless-core/transport"
)

// Server is a VLESS inbound: it accepts VLESS connections, authenticates the
// user, and forwards TCP/UDP traffic to the requested destination.
type Server struct {
	cfg       *Config
	validator *Validator
	log       *Logger

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

func NewServer(cfg *Config, log *Logger) (*Server, error) {
	if cfg.Role != "server" {
		return nil, fmt.Errorf("config role is %q, want server", cfg.Role)
	}
	v, err := NewValidator(cfg.Users)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, validator: v, log: log, conns: make(map[net.Conn]struct{})}, nil
}

// Addr returns the actual bound address. Useful when listening on ":0".
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve starts accepting connections and blocks until Close is called.
func (s *Server) Serve() error {
	ln, err := transport.Listen(s.cfg.Transport, s.cfg.Listen)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return nil
	}
	s.ln = ln
	s.mu.Unlock()

	s.log.Info("VLESS server listening on %s (%d users)", ln.Addr(), s.validator.Count())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.isClosed() {
				return nil
			}
			s.log.Warn("accept: %v", err)
			continue
		}
		s.track(conn, true)
		go func() {
			defer s.track(conn, false)
			s.handle(conn)
		}()
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) track(conn net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
		return
	}
	delete(s.conns, conn)
	_ = conn.Close()
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) handle(conn net.Conn) {
	if d := s.cfg.HandshakeTimeout(); d > 0 {
		_ = conn.SetDeadline(time.Now().Add(d))
	}

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	req, err := protocol.ReadRequestHeader(br, s.validator)
	if err != nil {
		s.log.Warn("reject %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Handshake is done; switch to the (optional) session-wide deadline.
	if d := s.cfg.IdleTimeout(); d > 0 {
		_ = conn.SetDeadline(time.Now().Add(d))
	} else {
		_ = conn.SetDeadline(time.Time{})
	}

	email, _ := s.validator.Get(req.UUID)
	s.log.Info("accept %s user=%s cmd=%d target=%s route=%d",
		conn.RemoteAddr(), email, req.Command, req.Address.String(), req.UUID.Route())

	if req.Addons != nil && req.Addons.Flow != "" {
		// The wire format is understood, but XTLS Vision's TLS record filter
		// and splice-copy data plane are deliberately out of scope. We forward
		// as a plain stream; see README for compatibility notes.
		s.log.Warn("flow %q is decoded but its data plane is not implemented; using plain forwarding", req.Addons.Flow)
	}

	switch req.Command {
	case protocol.CommandTCP, protocol.CommandUDP:
	case protocol.CommandMux, protocol.CommandRvs:
		s.log.Warn("command %d (Mux/Rvs) is not supported by this core", req.Command)
		return
	default:
		return
	}

	// Xray-core sends the response header immediately after parsing the request.
	if err := protocol.WriteResponseHeader(bw, &protocol.ResponseHeader{
		Version: req.Version,
		Addons:  &protocol.Addons{},
	}); err != nil {
		return
	}
	if err := bw.Flush(); err != nil {
		return
	}

	if req.Command == protocol.CommandUDP {
		if err := s.handleUDP(conn, br, bw, req); err != nil {
			s.log.Debug("udp session %s ended: %v", conn.RemoteAddr(), err)
		}
		return
	}

	target, err := net.DialTimeout("tcp", req.Address.String(), s.cfg.HandshakeTimeout())
	if err != nil {
		s.log.Warn("dial %s failed: %v", req.Address.String(), err)
		return
	}
	defer target.Close()
	if d := s.cfg.IdleTimeout(); d > 0 {
		_ = target.SetDeadline(time.Now().Add(d))
	}
	if err := relayStreams(conn, br, bw, target); err != nil {
		s.log.Debug("tcp session %s ended: %v", conn.RemoteAddr(), err)
	}
}

// handleUDP forwards length-prefixed VLESS datagrams to a single UDP target.
// Uplink and downlink run independently so multiple responses (or a response
// arriving later) are handled correctly.
func (s *Server) handleUDP(conn net.Conn, br *bufio.Reader, bw *bufio.Writer, req *protocol.RequestHeader) error {
	raddr, err := net.ResolveUDPAddr("udp", req.Address.String())
	if err != nil {
		return fmt.Errorf("resolve udp target: %w", err)
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("dial udp target: %w", err)
	}
	defer uc.Close()
	if d := s.cfg.IdleTimeout(); d > 0 {
		_ = uc.SetDeadline(time.Now().Add(d))
	}

	go func() {
		for {
			pkt, err := protocol.ReadPacket(br)
			if err != nil {
				_ = uc.Close()
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if _, err := uc.Write(pkt); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, protocol.MaxPacketLength)
	for {
		n, err := uc.Read(buf)
		if err != nil {
			return err
		}
		if err := protocol.WritePacket(bw, buf[:n]); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	}
}
