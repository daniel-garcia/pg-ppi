package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
)

const identity = "web.emojivoto.serviceaccount.identity.linkerd.cluster.local"

// goldenIPv4WithIdentity is byte-for-byte the output of the Linkerd proxy's
// encoder in linkerd2-proxy's encode_ipv4_with_identity_golden test.
func goldenIPv4WithIdentity() []byte {
	b := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,       // version 2, command PROXY
		0x11,       // AF_INET, STREAM
		0x00, 0x4A, // length = 74
		10, 1, 2, 3,
		10, 9, 8, 7,
	}
	b = binary.BigEndian.AppendUint16(b, 33000)
	b = binary.BigEndian.AppendUint16(b, 5432)
	b = append(b, 0xE0)
	b = binary.BigEndian.AppendUint16(b, 59)
	return append(b, identity...)
}

func TestReadGoldenIPv4WithIdentity(t *testing.T) {
	trailer := []byte("startup-bytes")
	r := bytes.NewReader(append(goldenIPv4WithIdentity(), trailer...))

	h, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	if h.Command != CommandProxy {
		t.Errorf("command = %v", h.Command)
	}
	if got, want := h.Source, netip.MustParseAddrPort("10.1.2.3:33000"); got != want {
		t.Errorf("source = %v, want %v", got, want)
	}
	if got, want := h.Destination, netip.MustParseAddrPort("10.9.8.7:5432"); got != want {
		t.Errorf("destination = %v, want %v", got, want)
	}
	id, ok := h.ClientID()
	if !ok || id != identity {
		t.Errorf("ClientID() = %q, %v", id, ok)
	}

	// The reader must be positioned exactly after the header.
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, trailer) {
		t.Errorf("trailing bytes = %q, want %q", rest, trailer)
	}
}

func TestReadNoIdentity(t *testing.T) {
	buf := Encode(netip.MustParseAddrPort("10.1.2.3:33000"), netip.MustParseAddrPort("10.9.8.7:5432"))
	h, err := Read(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.ClientID(); ok {
		t.Error("unexpected client identity")
	}
}

func TestReadMixedFamilyUnmapped(t *testing.T) {
	src := netip.AddrPortFrom(netip.MustParseAddr("10.1.2.3").Unmap(), 33000)
	dst := netip.MustParseAddrPort("[fd00::2]:5432")
	buf := Encode(src, dst)
	if buf[13] != famTCP6 {
		t.Fatalf("family = %#x, want TCP6", buf[13])
	}
	h, err := Read(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if h.Source != src {
		t.Errorf("source = %v, want %v (unmapped)", h.Source, src)
	}
	if h.Destination != dst {
		t.Errorf("destination = %v, want %v", h.Destination, dst)
	}
}

func TestEncodeMatchesGolden(t *testing.T) {
	got := Encode(
		netip.MustParseAddrPort("10.1.2.3:33000"),
		netip.MustParseAddrPort("10.9.8.7:5432"),
		TLV{Type: TLVTypeLinkerdClientID, Value: []byte(identity)},
	)
	if !bytes.Equal(got, goldenIPv4WithIdentity()) {
		t.Errorf("Encode mismatch\n got %x\nwant %x", got, goldenIPv4WithIdentity())
	}
}

func TestReadErrors(t *testing.T) {
	golden := goldenIPv4WithIdentity()

	tests := map[string][]byte{
		"postgres startup instead of header": {0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F, 0, 0, 0, 0, 0, 0, 0, 0},
		"truncated prefix":                   golden[:10],
		"truncated body":                     golden[:40],
		"bad version": func() []byte {
			b := bytes.Clone(golden)
			b[12] = 0x11
			return b
		}(),
		"bad family": func() []byte {
			b := bytes.Clone(golden)
			b[13] = 0x41
			return b
		}(),
		"TLV overrun": func() []byte {
			b := bytes.Clone(golden)
			binary.BigEndian.PutUint16(b[29:31], 200)
			return b
		}(),
		"oversized": func() []byte {
			b := bytes.Clone(golden[:16])
			binary.BigEndian.PutUint16(b[14:16], maxHeaderLen+1)
			return b
		}(),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(input)); err == nil {
				t.Fatal("expected error")
			}
		})
	}

	if _, err := Read(bytes.NewReader(tests["postgres startup instead of header"])); !errors.Is(err, ErrNoSignature) {
		t.Errorf("err = %v, want ErrNoSignature", err)
	}
}
