package core

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/purepoorx/vl-core/protocol"
)

// handleHTTP implements the HTTP CONNECT proxy method. Plain HTTP requests
// (GET/POST over an absolute URI) are not supported by this minimal core.
func (c *Client) handleHTTP(local net.Conn) {
	br := bufio.NewReader(local)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 3 || !strings.EqualFold(parts[0], "CONNECT") {
		_, _ = io.WriteString(local, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	// Consume all remaining request headers.
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	host, portStr, err := net.SplitHostPort(parts[1])
	if err != nil {
		_, _ = io.WriteString(local, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		_, _ = io.WriteString(local, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	target := protocol.ParseAddress(host, uint16(port))

	vc, err := c.openVLESS(context.Background(), target, protocol.CommandTCP)
	if err != nil {
		c.log.Warn("vless dial %s failed: %v", target.String(), err)
		_, _ = io.WriteString(local, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer vc.Close()

	if _, err := io.WriteString(local, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	c.log.Debug("http CONNECT %s", target.String())
	if err := c.relayTCP(local, br, vc); err != nil {
		c.log.Debug("http session ended: %v", err)
	}
}
