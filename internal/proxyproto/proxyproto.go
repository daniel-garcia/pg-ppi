// Package proxyproto decodes HAProxy PROXY protocol v2 headers, including
// the Linkerd-specific TLV that carries the client's verified mTLS identity.
//
// See https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// Signature is the 12-byte preamble that begins every v2 header.
var Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// TLVTypeLinkerdClientID is the TLV type the Linkerd inbound proxy uses to
// carry the verified mTLS client identity (e.g.
// "billing.prod.serviceaccount.identity.linkerd.cluster.local").
const TLVTypeLinkerdClientID = 0xE0

// maxHeaderLen bounds the variable-length part of the header. The spec allows
// up to 65535 bytes, but anything the Linkerd proxy emits is far smaller.
const maxHeaderLen = 4096

// Command is the v2 command nibble.
type Command uint8

const (
	// CommandLocal marks a connection established by the proxy itself (e.g.
	// a health check); the address block must be ignored.
	CommandLocal Command = 0x0
	// CommandProxy marks a relayed connection.
	CommandProxy Command = 0x1
)

// Address family / transport protocol byte values.
const (
	famUnspec   = 0x00
	famTCP4     = 0x11
	famUDP4     = 0x12
	famTCP6     = 0x21
	famUDP6     = 0x22
	famUnixStr  = 0x31
	famUnixDgrm = 0x32
)

// TLV is a single type-length-value extension.
type TLV struct {
	Type  uint8
	Value []byte
}

// Header is a decoded PROXY protocol v2 header.
type Header struct {
	Command     Command
	Source      netip.AddrPort
	Destination netip.AddrPort
	TLVs        []TLV
}

// ClientID returns the Linkerd verified client identity, if present.
func (h *Header) ClientID() (string, bool) {
	for _, t := range h.TLVs {
		if t.Type == TLVTypeLinkerdClientID {
			return string(t.Value), true
		}
	}
	return "", false
}

var (
	// ErrNoSignature is returned when the stream does not begin with a v2
	// signature (i.e. the connection did not come through a proxy that
	// speaks PROXY protocol v2).
	ErrNoSignature = errors.New("proxyproto: missing PROXY protocol v2 signature")
)

// Read reads exactly one v2 header from r. It never reads past the end of the
// header, so r can be handed to the next protocol parser afterwards.
func Read(r io.Reader) (*Header, error) {
	var prefix [16]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("proxyproto: reading header prefix: %w", err)
	}
	if !bytes.Equal(prefix[:12], Signature) {
		return nil, ErrNoSignature
	}
	if v := prefix[12] >> 4; v != 2 {
		return nil, fmt.Errorf("proxyproto: unsupported version %d", v)
	}
	cmd := Command(prefix[12] & 0x0F)
	if cmd != CommandLocal && cmd != CommandProxy {
		return nil, fmt.Errorf("proxyproto: unsupported command %#x", uint8(cmd))
	}
	fam := prefix[13]
	n := int(binary.BigEndian.Uint16(prefix[14:16]))
	if n > maxHeaderLen {
		return nil, fmt.Errorf("proxyproto: header length %d exceeds limit %d", n, maxHeaderLen)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("proxyproto: reading header body: %w", err)
	}
	return parseBody(cmd, fam, body)
}

func parseBody(cmd Command, fam byte, body []byte) (*Header, error) {
	h := &Header{Command: cmd}

	var addrLen int
	switch fam {
	case famUnspec:
		addrLen = 0
	case famTCP4, famUDP4:
		addrLen = 12
	case famTCP6, famUDP6:
		addrLen = 36
	case famUnixStr, famUnixDgrm:
		addrLen = 216
	default:
		return nil, fmt.Errorf("proxyproto: unsupported address family %#x", fam)
	}
	if len(body) < addrLen {
		return nil, fmt.Errorf("proxyproto: address block truncated (%d < %d)", len(body), addrLen)
	}

	switch fam {
	case famTCP4, famUDP4:
		src := netip.AddrFrom4([4]byte(body[0:4]))
		dst := netip.AddrFrom4([4]byte(body[4:8]))
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[8:10]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(body[10:12]))
	case famTCP6, famUDP6:
		// The Linkerd proxy promotes mixed families to IPv6 using
		// IPv4-mapped addresses; unmap them so they read naturally.
		src := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		dst := netip.AddrFrom16([16]byte(body[16:32])).Unmap()
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[32:34]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(body[34:36]))
	}

	tlvs := body[addrLen:]
	for len(tlvs) > 0 {
		if len(tlvs) < 3 {
			return nil, errors.New("proxyproto: truncated TLV header")
		}
		typ := tlvs[0]
		l := int(binary.BigEndian.Uint16(tlvs[1:3]))
		if len(tlvs) < 3+l {
			return nil, fmt.Errorf("proxyproto: TLV %#x length %d overruns header", typ, l)
		}
		h.TLVs = append(h.TLVs, TLV{Type: typ, Value: tlvs[3 : 3+l]})
		tlvs = tlvs[3+l:]
	}

	return h, nil
}

// Encode serializes a PROXY command header for TCP source/destination
// addresses with the given TLVs. It mirrors the Linkerd proxy's encoder and
// exists so tests (and local tooling) can impersonate the proxy.
func Encode(src, dst netip.AddrPort, tlvs ...TLV) []byte {
	var fam byte
	var addrs []byte
	s, d := src.Addr(), dst.Addr()
	if s.Is4() && d.Is4() {
		fam = famTCP4
		s4, d4 := s.As4(), d.As4()
		addrs = append(append(addrs, s4[:]...), d4[:]...)
	} else {
		fam = famTCP6
		s16, d16 := s.As16(), d.As16()
		addrs = append(append(addrs, s16[:]...), d16[:]...)
	}
	addrs = binary.BigEndian.AppendUint16(addrs, src.Port())
	addrs = binary.BigEndian.AppendUint16(addrs, dst.Port())
	for _, t := range tlvs {
		addrs = append(addrs, t.Type)
		addrs = binary.BigEndian.AppendUint16(addrs, uint16(len(t.Value)))
		addrs = append(addrs, t.Value...)
	}

	buf := make([]byte, 0, 16+len(addrs))
	buf = append(buf, Signature...)
	buf = append(buf, 0x20|byte(CommandProxy), fam)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(addrs)))
	return append(buf, addrs...)
}
