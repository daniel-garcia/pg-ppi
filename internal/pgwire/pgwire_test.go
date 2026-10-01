package pgwire

import (
	"bytes"
	"errors"
	"testing"
)

func TestStartupRoundTrip(t *testing.T) {
	in := &StartupMessage{
		ProtocolVersion: 3 << 16,
		Params: []Param{
			{"user", "billing_app"},
			{"database", "app"},
			{"application_name", "psql"},
		},
	}
	p, err := ReadPacket(bytes.NewReader(in.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseStartupMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in.Encode(), out.Encode()) {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if u, _ := out.Get("user"); u != "billing_app" {
		t.Errorf("user = %q", u)
	}

	out.Set("user", "other")
	out.Set("options", "-c x=y")
	if u, _ := out.Get("user"); u != "other" {
		t.Errorf("user = %q", u)
	}
	if len(out.Params) != 4 {
		t.Errorf("params = %+v", out.Params)
	}
}

func TestReadPacketSSLRequest(t *testing.T) {
	p, err := ReadPacket(bytes.NewReader(SSLRequest()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Code != SSLRequestCode || len(p.Payload) != 0 {
		t.Errorf("got %+v", p)
	}
}

func TestReadPacketErrors(t *testing.T) {
	if _, err := ReadPacket(bytes.NewReader([]byte{0x16, 0x03, 0x01})); !errors.Is(err, ErrDirectTLS) {
		t.Errorf("direct TLS: err = %v", err)
	}
	if _, err := ReadPacket(bytes.NewReader([]byte{0, 0, 0, 4, 0, 3, 0, 0})); err == nil {
		t.Error("short length: expected error")
	}
	if _, err := ReadPacket(bytes.NewReader([]byte{0, 1, 0, 0, 0, 3, 0, 0})); err == nil {
		t.Error("oversized: expected error")
	}
}

func TestParseStartupMessageErrors(t *testing.T) {
	for name, p := range map[string]*Packet{
		"protocol 2":   {Code: 2 << 16, Payload: []byte{0}},
		"unterminated": {Code: 3 << 16, Payload: []byte("user\x00x")},
		"no value":     {Code: 3 << 16, Payload: []byte("user")},
		"trailing":     {Code: 3 << 16, Payload: []byte("\x00junk")},
	} {
		if _, err := ParseStartupMessage(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestErrorResponse(t *testing.T) {
	b := ErrorResponse(SQLStateInvalidAuthorization, "nope")
	want := "E\x00\x00\x00\x20SFATAL\x00VFATAL\x00C28000\x00Mnope\x00\x00"
	if string(b) != want {
		t.Errorf("got %q\nwant %q", b, want)
	}
}
