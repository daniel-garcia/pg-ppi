// Package pgwire implements the small subset of the PostgreSQL frontend/backend
// protocol needed before a connection is handed off to a byte splice: the
// untyped startup-phase packets (SSLRequest, GSSENCRequest, CancelRequest,
// StartupMessage) and ErrorResponse.
//
// See https://www.postgresql.org/docs/current/protocol-message-formats.html.
package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Startup-phase request codes.
const (
	SSLRequestCode    uint32 = 80877103
	GSSENCRequestCode uint32 = 80877104
	CancelRequestCode uint32 = 80877102
)

// maxStartupPacketLen matches PostgreSQL's MAX_STARTUP_PACKET_LENGTH.
const maxStartupPacketLen = 10000

// tlsHandshakeRecord is the first byte of a TLS ClientHello, sent by clients
// using sslnegotiation=direct (PostgreSQL 17+).
const tlsHandshakeRecord = 0x16

// ErrDirectTLS is returned when a client attempts direct TLS negotiation.
var ErrDirectTLS = errors.New("pgwire: client attempted direct TLS negotiation")

// Packet is an untyped startup-phase packet: a request code (or protocol
// version, for a StartupMessage) and the remaining payload.
type Packet struct {
	Code    uint32
	Payload []byte
}

// ProtocolMajor returns the protocol major version if this is a
// StartupMessage.
func (p *Packet) ProtocolMajor() uint32 { return p.Code >> 16 }

// Encode serializes the packet including its length prefix.
func (p *Packet) Encode() []byte {
	b := make([]byte, 8, 8+len(p.Payload))
	binary.BigEndian.PutUint32(b[0:4], uint32(8+len(p.Payload)))
	binary.BigEndian.PutUint32(b[4:8], p.Code)
	return append(b, p.Payload...)
}

// ReadPacket reads one untyped startup-phase packet from r.
func ReadPacket(r io.Reader) (*Packet, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return nil, err
	}
	if hdr[0] == tlsHandshakeRecord {
		return nil, ErrDirectTLS
	}
	if _, err := io.ReadFull(r, hdr[1:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[0:4])
	if n < 8 || n > maxStartupPacketLen {
		return nil, fmt.Errorf("pgwire: invalid startup packet length %d", n)
	}
	p := &Packet{Code: binary.BigEndian.Uint32(hdr[4:8]), Payload: make([]byte, n-8)}
	if _, err := io.ReadFull(r, p.Payload); err != nil {
		return nil, err
	}
	return p, nil
}

// SSLRequest returns an encoded SSLRequest packet.
func SSLRequest() []byte { return (&Packet{Code: SSLRequestCode}).Encode() }

// Param is a single StartupMessage parameter.
type Param struct{ Name, Value string }

// StartupMessage is a decoded StartupMessage. Parameter order is preserved.
type StartupMessage struct {
	ProtocolVersion uint32
	Params          []Param
}

// ParseStartupMessage decodes a StartupMessage packet.
func ParseStartupMessage(p *Packet) (*StartupMessage, error) {
	if p.ProtocolMajor() != 3 {
		return nil, fmt.Errorf("pgwire: unsupported protocol version %d.%d", p.Code>>16, p.Code&0xFFFF)
	}
	m := &StartupMessage{ProtocolVersion: p.Code}
	b := p.Payload
	for {
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return nil, errors.New("pgwire: unterminated startup parameter")
		}
		if i == 0 {
			if len(b) != 1 {
				return nil, errors.New("pgwire: trailing bytes after startup parameters")
			}
			return m, nil
		}
		name := string(b[:i])
		b = b[i+1:]
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			return nil, fmt.Errorf("pgwire: unterminated value for startup parameter %q", name)
		}
		m.Params = append(m.Params, Param{Name: name, Value: string(b[:j])})
		b = b[j+1:]
	}
}

// Get returns the value of the named parameter.
func (m *StartupMessage) Get(name string) (string, bool) {
	for _, p := range m.Params {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// Set replaces (or appends) the named parameter.
func (m *StartupMessage) Set(name, value string) {
	for i := range m.Params {
		if m.Params[i].Name == name {
			m.Params[i].Value = value
			return
		}
	}
	m.Params = append(m.Params, Param{Name: name, Value: value})
}

// Encode serializes the StartupMessage including its length prefix.
func (m *StartupMessage) Encode() []byte {
	var payload []byte
	for _, p := range m.Params {
		payload = append(payload, p.Name...)
		payload = append(payload, 0)
		payload = append(payload, p.Value...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0)
	return (&Packet{Code: m.ProtocolVersion, Payload: payload}).Encode()
}

// SQLSTATE codes used when rejecting connections.
const (
	SQLStateInvalidAuthorization = "28000"
	SQLStateProtocolViolation    = "08P01"
	SQLStateConnectionFailure    = "08006"
)

// ErrorResponse returns an encoded FATAL ErrorResponse message.
func ErrorResponse(sqlstate, message string) []byte {
	var body []byte
	field := func(code byte, v string) {
		body = append(body, code)
		body = append(body, v...)
		body = append(body, 0)
	}
	field('S', "FATAL")
	field('V', "FATAL")
	field('C', sqlstate)
	field('M', message)
	body = append(body, 0)

	b := make([]byte, 5, 5+len(body))
	b[0] = 'E'
	binary.BigEndian.PutUint32(b[1:5], uint32(4+len(body)))
	return append(b, body...)
}
