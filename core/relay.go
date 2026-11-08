package core

import (
	"bufio"
	"io"
	"net"
)

type closeWriter interface {
	CloseWrite() error
}

func tryCloseWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
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
func relayStreams(client net.Conn, clientR io.Reader, clientW *bufio.Writer, target net.Conn) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, clientR)
		tryCloseWrite(target)
		errCh <- err
	}()
	go func() {
		err := copyAndFlush(clientW, target)
		tryCloseWrite(client)
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
