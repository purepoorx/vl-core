package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func mustUUID(t *testing.T, s string) UUID {
	t.Helper()
	u, err := ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}
	return b
}

func TestUUID(t *testing.T) {
	u := mustUUID(t, testUUID)
	if got := u.String(); got != testUUID {
		t.Fatalf("String() = %q", got)
	}
	if got := hex.EncodeToString(u[:]); got != "b831381d63244d53ad4f8cda48b30811" {
		t.Fatalf("bytes = %s", got)
	}
	u2, err := ParseUUID("B831381D63244D53AD4F8CDA48B30811")
	if err != nil || u2 != u {
		t.Fatalf("unhyphenated parse failed: %v %v", u2, err)
	}
	for _, bad := range []string{"", "abc", "b831381d_6324-4d53-ad4f-8cda48b30811", "zz31381d-6324-4d53-ad4f-8cda48b30811"} {
		if _, err := ParseUUID(bad); err == nil {
			t.Errorf("ParseUUID(%q) should fail", bad)
		}
	}
	n := NormalizeUUID(u)
	if n[6] != 0 || n[7] != 0 || n[0] != u[0] {
		t.Fatalf("NormalizeUUID = %s", hex.EncodeToString(n[:]))
	}
	if u.Route() != 0x4d53 {
		t.Fatalf("Route() = %x", u.Route())
	}
}

func TestAddonsWireFormat(t *testing.T) {
	if b := MarshalAddons(&Addons{}); len(b) != 0 {
		t.Fatalf("empty addons should encode to zero bytes, got %x", b)
	}

	// Golden bytes produced by proto.Marshal(&Addons{Flow:"xtls-rprx-vision"}).
	want := "0a10" + hex.EncodeToString([]byte(FlowVision))
	got := hex.EncodeToString(MarshalAddons(&Addons{Flow: FlowVision}))
	if got != want {
		t.Fatalf("vision addons = %s, want %s", got, want)
	}

	a, err := UnmarshalAddons(fromHex(t, want))
	if err != nil || a.Flow != FlowVision || len(a.Seed) != 0 {
		t.Fatalf("UnmarshalAddons = %+v, %v", a, err)
	}

	// Seed + unknown field must survive a decode/encode round trip.
	seed := []byte{0x01, 0x02, 0xfe}
	raw := appendVarint(nil, 9<<3|2)
	raw = appendVarint(raw, 3)
	raw = append(raw, 'x', 'y', 'z')
	original := append(MarshalAddons(&Addons{Flow: FlowVision, Seed: seed}), raw...)
	a, err = UnmarshalAddons(original)
	if err != nil {
		t.Fatal(err)
	}
	if a.Flow != FlowVision || !bytes.Equal(a.Seed, seed) || !bytes.Equal(a.Raw, raw) {
		t.Fatalf("round trip lost data: %+v", a)
	}
	if !bytes.Equal(MarshalAddons(a), original) {
		t.Fatal("re-encoded addons differ from original")
	}

	if _, err := UnmarshalAddons([]byte{0x80}); err == nil {
		t.Fatal("truncated varint should fail")
	}
	if _, err := UnmarshalAddons([]byte{0x0a, 0x05, 'a'}); err == nil {
		t.Fatal("truncated length-delimited field should fail")
	}
}

func TestAddressRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr Address
		hex  string
	}{
		{"ipv4", Address{IP: net.ParseIP("1.2.3.4").To4(), Port: 443}, "01bb0101020304"},
		{"ipv6", Address{IP: net.ParseIP("2001:db8::1"), Port: 80}, "00500320010db8000000000000000000000001"},
		{"domain", Address{Domain: "www.example.com", Port: 443}, "01bb020f7777772e6578616d706c652e636f6d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := AppendAddressPort(nil, tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(b); got != tc.hex {
				t.Fatalf("encoded = %s, want %s", got, tc.hex)
			}
			back, err := ReadAddressPort(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			if back.String() != tc.addr.String() {
				t.Fatalf("round trip = %s, want %s", back.String(), tc.addr.String())
			}
		})
	}
	if err := (Address{Port: 80}).Validate(); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("empty address should fail, got %v", err)
	}
	if err := (Address{Domain: strings.Repeat("a", 256), Port: 80}).Validate(); !errors.Is(err, ErrDomainTooLong) {
		t.Fatalf("long domain should fail, got %v", err)
	}
	// Xray converts numeric-looking domains back into IP addresses.
	b := fromHex(t, "00350207312e322e332e34")
	back, err := ReadAddressPort(bytes.NewReader(b))
	if err != nil || back.IsDomain() || back.IP.String() != "1.2.3.4" {
		t.Fatalf("numeric domain conversion = %+v, %v", back, err)
	}
}

func TestRequestHeaderGoldenBytes(t *testing.T) {
	// This byte sequence is exactly what Xray-core's EncodeRequestHeader emits
	// for UUID/CommandTCP/www.example.com:443 with empty addons.
	golden := "00" +
		"b831381d63244d53ad4f8cda48b30811" +
		"00" + // addons length
		"01" + // TCP
		"01bb" + // port 443
		"020f" + "7777772e6578616d706c652e636f6d"

	u := mustUUID(t, testUUID)
	h := &RequestHeader{
		Version: Version,
		UUID:    u,
		Addons:  &Addons{},
		Command: CommandTCP,
		Address: ParseAddress("www.example.com", 443),
	}
	var buf bytes.Buffer
	if err := WriteRequestHeader(&buf, h); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != golden {
		t.Fatalf("encoded =\n%s\nwant\n%s", got, golden)
	}

	parsed, err := ReadRequestHeader(bytes.NewReader(buf.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.UUID != u || parsed.Command != CommandTCP || parsed.Address.String() != "www.example.com:443" {
		t.Fatalf("parsed = %+v", parsed)
	}
	if !parsed.Addons.IsEmpty() {
		t.Fatalf("addons should be empty: %+v", parsed.Addons)
	}
}

func TestRequestHeaderVisionAndMux(t *testing.T) {
	u := mustUUID(t, testUUID)
	for _, tc := range []struct {
		name    string
		command Command
		addr    Address
		addons  *Addons
	}{
		{"vision-tcp", CommandTCP, ParseAddress("1.2.3.4", 443), &Addons{Flow: FlowVision}},
		{"udp-ipv6", CommandUDP, ParseAddress("2001:db8::1", 53), &Addons{Seed: []byte{1, 2, 3}}},
		{"mux", CommandMux, Address{}, &Addons{}},
		{"rvs", CommandRvs, Address{}, &Addons{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &RequestHeader{Version: Version, UUID: u, Command: tc.command, Address: tc.addr, Addons: tc.addons}
			var buf bytes.Buffer
			if err := WriteRequestHeader(&buf, h); err != nil {
				t.Fatal(err)
			}
			parsed, err := ReadRequestHeader(bytes.NewReader(buf.Bytes()), nil)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.UUID != u || parsed.Command != tc.command {
				t.Fatalf("round trip mismatch: %+v", parsed)
			}
			if parsed.Addons.Flow != tc.addons.Flow || string(parsed.Addons.Seed) != string(tc.addons.Seed) {
				t.Fatalf("addons mismatch: %+v", parsed.Addons)
			}
			if tc.command.HasAddress() && parsed.Address.String() != tc.addr.String() {
				t.Fatalf("address = %s, want %s", parsed.Address.String(), tc.addr.String())
			}
			if !tc.command.HasAddress() && parsed.Address.Domain == "" {
				t.Fatal("Mux/Rvs should get their well-known pseudo address")
			}
		})
	}
}

func TestValidatorAndErrors(t *testing.T) {
	u := mustUUID(t, testUUID)
	v := ValidatorFunc(func(got UUID) (string, bool) {
		return "alice", NormalizeUUID(got) == NormalizeUUID(u)
	})
	h := &RequestHeader{Version: Version, UUID: u, Command: CommandTCP, Address: ParseAddress("example.com", 80), Addons: &Addons{}}
	var buf bytes.Buffer
	if err := WriteRequestHeader(&buf, h); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if _, err := ReadRequestHeader(bytes.NewReader(raw), v); err != nil {
		t.Fatalf("valid user rejected: %v", err)
	}

	// A UUID with modified routing bytes must still authenticate.
	modified := append([]byte(nil), raw...)
	modified[7], modified[8] = 0x12, 0x34
	if _, err := ReadRequestHeader(bytes.NewReader(modified), v); err != nil {
		t.Fatalf("routing-byte UUID rejected: %v", err)
	}

	reject := ValidatorFunc(func(UUID) (string, bool) { return "", false })
	if _, err := ReadRequestHeader(bytes.NewReader(raw), reject); !errors.Is(err, ErrUserRejected) {
		t.Fatalf("want ErrUserRejected, got %v", err)
	}

	badVersion := append([]byte(nil), raw...)
	badVersion[0] = 1
	if _, err := ReadRequestHeader(bytes.NewReader(badVersion), v); !errors.Is(err, ErrVersion) {
		t.Fatalf("want ErrVersion, got %v", err)
	}

	// command byte follows: version(1) + uuid(16) + addonsLen(1) = 18
	badCommand := append([]byte(nil), raw...)
	badCommand[18] = 0x63
	if _, err := ReadRequestHeader(bytes.NewReader(badCommand), v); !errors.Is(err, ErrBadCommand) {
		t.Fatalf("want ErrBadCommand, got %v", err)
	}

	badAddr := append([]byte(nil), raw...)
	badAddr[21] = 0x09 // version(1)+uuid(16)+addonsLen(1)+cmd(1)+port(2) = 21
	if _, err := ReadRequestHeader(bytes.NewReader(badAddr), v); !errors.Is(err, ErrBadAddressType) {
		t.Fatalf("want ErrBadAddressType, got %v", err)
	}

	if _, err := ReadRequestHeader(bytes.NewReader(raw[:10]), v); !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("want truncation error, got %v", err)
	}

	h.Addons = &Addons{Flow: strings.Repeat("x", 300)}
	if err := WriteRequestHeader(io.Discard, h); !errors.Is(err, ErrAddonsTooLong) {
		t.Fatalf("want ErrAddonsTooLong, got %v", err)
	}
}

func TestResponseHeader(t *testing.T) {
	h := &ResponseHeader{Version: Version, Addons: &Addons{}}
	var buf bytes.Buffer
	if err := WriteResponseHeader(&buf, h); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != "0000" {
		t.Fatalf("empty response header = %s, want 0000", got)
	}
	back, err := ReadResponseHeader(bytes.NewReader(buf.Bytes()), Version)
	if err != nil || back.Version != Version || !back.Addons.IsEmpty() {
		t.Fatalf("round trip = %+v, %v", back, err)
	}

	h.Addons = &Addons{Flow: FlowVision, Seed: []byte{0xaa}}
	buf.Reset()
	if err := WriteResponseHeader(&buf, h); err != nil {
		t.Fatal(err)
	}
	back, err = ReadResponseHeader(bytes.NewReader(buf.Bytes()), Version)
	if err != nil || back.Addons.Flow != FlowVision || !bytes.Equal(back.Addons.Seed, []byte{0xaa}) {
		t.Fatalf("vision response = %+v, %v", back, err)
	}
	if _, err := ReadResponseHeader(bytes.NewReader(buf.Bytes()), 1); !errors.Is(err, ErrResponseVersion) {
		t.Fatalf("want ErrResponseVersion, got %v", err)
	}
}

func TestPacketFraming(t *testing.T) {
	var buf bytes.Buffer
	packets := [][]byte{[]byte("hello"), {0x00, 0xff}, {}}
	for _, p := range packets {
		if err := WritePacket(&buf, p); err != nil {
			t.Fatal(err)
		}
	}
	if got := hex.EncodeToString(buf.Bytes()); got != "000568656c6c6f000200ff0000" {
		t.Fatalf("framed = %s", got)
	}
	for i, want := range packets {
		got, err := ReadPacket(&buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d = %x, want %x", i, got, want)
		}
	}
	if _, err := ReadPacket(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	if err := WritePacket(io.Discard, make([]byte, MaxPacketLength+1)); !errors.Is(err, ErrPacketTooLong) {
		t.Fatalf("want ErrPacketTooLong, got %v", err)
	}
}
