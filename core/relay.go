package core

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

// tryCloseWrite half-closes c when its transport supports it and reports
// whether it did. *net.TCPConn and *tls.Conn do; wsConn cannot, because
// RFC 6455 only offers a whole-connection Close frame, never a half-close.
func tryCloseWrite(c net.Conn) bool {
	cw, ok := c.(closeWriter)
	if !ok {
		return false
	}
	return cw.CloseWrite() == nil
}

// halfCloseGuard bounds the wait that follows a half-close the peer cannot see.
//
// TCP, including TLS, signals end-of-stream with a FIN. RFC 6455 has no such
// primitive: a WebSocket can only be closed as a whole, and telling the peer
// "no more data from me" would also stop it from sending the response. So when
// one direction finishes over WS, the other end keeps waiting for data that
// will never come - and with idle=0 (the default) it waits forever, pinning
// both goroutines and the connection.
//
// The guard closes the connection once the surviving direction has been
// completely silent for the configured duration. Every byte read there pushes
// the deadline forward, so a slow but still active transfer is never cut off;
// only a peer that has genuinely gone quiet gets reaped.
type halfCloseGuard struct {
	conn net.Conn
	idle time.Duration

	mu    sync.Mutex
	timer *time.Timer
	armed bool
}

func newHalfCloseGuard(conn net.Conn, idle time.Duration) *halfCloseGuard {
	return &halfCloseGuard{conn: conn, idle: idle}
}

// arm starts the countdown. It is a no-op when the guard is disabled.
func (g *halfCloseGuard) arm() {
	if g == nil || g.idle <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed = true
	if g.timer != nil {
		g.timer.Reset(g.idle)
		return
	}
	g.timer = time.AfterFunc(g.idle, func() {
		_ = g.conn.Close()
	})
}

// touch postpones the countdown after traffic on the surviving direction.
func (g *halfCloseGuard) touch() {
	if g == nil || g.idle <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.armed && g.timer != nil {
		g.timer.Reset(g.idle)
	}
}

// stop cancels the countdown once both directions have finished.
func (g *halfCloseGuard) stop() {
	if g == nil || g.idle <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed = false
	if g.timer != nil {
		g.timer.Stop()
	}
}

// touchReader postpones a halfCloseGuard whenever bytes actually arrive.
type touchReader struct {
	r io.Reader
	g *halfCloseGuard
}

func (t touchReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.g.touch()
	}
	return n, err
}

// copyAndFlush copies src into a buffered writer and flushes after every read.
// A plain io.Copy would stall because bufio.Writer only flushes when full.
func copyAndFlush(dst *bufio.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			if ferr := dst.Flush(); ferr != nil {
				return ferr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// relayStreams pumps bytes between a buffered client connection and a raw
// target connection. Each direction half-closes its peer when it finishes, so
// EOF propagates correctly in both directions (important for HTTP, SSH, ...).
//
// When the client side is a WebSocket, that half-close is impossible: the
// guard keeps the session from waiting forever for a FIN that will never
// arrive. halfClose <= 0 disables it.
func relayStreams(client net.Conn, clientR io.Reader, clientW *bufio.Writer, target net.Conn, halfClose time.Duration) error {
	guard := newHalfCloseGuard(client, halfClose)
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, touchReader{r: clientR, g: guard})
		tryCloseWrite(target)
		guard.stop()
		errCh <- err
	}()
	go func() {
		err := copyAndFlush(clientW, target)
		// The target is done. Without CloseWrite the client cannot see the end
		// of the response, so bound the wait instead of leaking the session.
		if err == nil && !tryCloseWrite(client) {
			guard.arm()
		}
		errCh <- err
	}()
	first := <-errCh
	second := <-errCh
	if first != nil && first != io.EOF {
		return first
	}
	if second != nil && second != io.EOF {
		return second
	}
	return nil
}
