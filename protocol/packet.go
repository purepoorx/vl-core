package protocol

import (
	"encoding/binary"
	"io"
)

// VLESS UDP carries datagrams as a stream of length-prefixed packets:
//
//	+--------+-------------------+
//	| 2 bytes| length, big endian|
//	| N bytes| datagram payload  |
//	+--------+-------------------+
//
// Both directions use the same framing. Xray-core calls these the
// MultiLengthPacketWriter and LengthPacketReader.

// WritePacket writes one length-prefixed datagram.
func WritePacket(w io.Writer, p []byte) error {
	if len(p) > MaxPacketLength {
		return ErrPacketTooLong
	}
	var b []byte
	b = append(b, byte(len(p)>>8), byte(len(p)))
	b = append(b, p...)
	return writeAll(w, b)
}

// ReadPacket reads one length-prefixed datagram.
func ReadPacket(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 {
		return []byte{}, nil
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// AppendPacket appends a framed datagram to dst without performing I/O.
func AppendPacket(dst []byte, p []byte) ([]byte, error) {
	if len(p) > MaxPacketLength {
		return dst, ErrPacketTooLong
	}
	dst = append(dst, byte(len(p)>>8), byte(len(p)))
	return append(dst, p...), nil
}
