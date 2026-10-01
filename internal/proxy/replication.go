package proxy

import (
	"fmt"
	"strings"
)

// ReplicationKind is the kind of connection requested by the StartupMessage
// "replication" parameter.
type ReplicationKind int

const (
	// ReplicationNone is an ordinary SQL connection.
	ReplicationNone ReplicationKind = iota
	// ReplicationLogical (replication=database) is a walsender connected to
	// one database, used for logical decoding (Debezium, pglogrepl, logical
	// subscriptions, ...).
	ReplicationLogical
	// ReplicationPhysical (replication=true) streams the cluster's entire
	// WAL (pg_receivewal, pg_basebackup, standbys).
	ReplicationPhysical
)

func (k ReplicationKind) String() string {
	switch k {
	case ReplicationLogical:
		return "logical"
	case ReplicationPhysical:
		return "physical"
	}
	return "none"
}

// ClassifyReplication interprets the "replication" startup parameter the
// same way PostgreSQL does: the exact string "database" means logical;
// otherwise the value must be a PostgreSQL boolean (true/false, on/off,
// yes/no, 1/0, or any unambiguous case-insensitive prefix of those).
func ClassifyReplication(value string, present bool) (ReplicationKind, error) {
	if !present {
		return ReplicationNone, nil
	}
	if value == "database" {
		return ReplicationLogical, nil
	}
	b, ok := parsePGBool(value)
	if !ok {
		return ReplicationNone, fmt.Errorf("invalid value for parameter \"replication\": %q", value)
	}
	if b {
		return ReplicationPhysical, nil
	}
	return ReplicationNone, nil
}

// parsePGBool mirrors PostgreSQL's parse_bool_with_len.
func parsePGBool(s string) (value, ok bool) {
	l := strings.ToLower(s)
	prefixOf := func(word string, minLen int) bool {
		return len(l) >= minLen && strings.HasPrefix(word, l)
	}
	switch {
	case l == "":
		return false, false
	case prefixOf("true", 1), prefixOf("yes", 1), prefixOf("on", 2), l == "1":
		return true, true
	case prefixOf("false", 1), prefixOf("no", 1), prefixOf("off", 2), l == "0":
		return false, true
	}
	return false, false
}

// ReplicationPolicy selects which replication connections pgppi forwards.
// Whatever is forwarded is still subject to PostgreSQL's own checks: the
// role must have the REPLICATION attribute, and physical replication also
// needs a pg_hba.conf line whose database column is "replication".
type ReplicationPolicy string

const (
	// ReplicationPolicyNone rejects all replication connections.
	ReplicationPolicyNone ReplicationPolicy = "none"
	// ReplicationPolicyLogical allows logical (replication=database) only.
	ReplicationPolicyLogical ReplicationPolicy = "logical"
	// ReplicationPolicyAll allows logical and physical replication.
	ReplicationPolicyAll ReplicationPolicy = "all"
)

// ParseReplicationPolicy validates a ReplicationPolicy string.
func ParseReplicationPolicy(s string) (ReplicationPolicy, error) {
	switch p := ReplicationPolicy(s); p {
	case ReplicationPolicyNone, ReplicationPolicyLogical, ReplicationPolicyAll:
		return p, nil
	}
	return "", fmt.Errorf("invalid replication policy %q (want %q, %q or %q)",
		s, ReplicationPolicyNone, ReplicationPolicyLogical, ReplicationPolicyAll)
}

// Allows reports whether the policy permits a connection of kind k.
func (p ReplicationPolicy) Allows(k ReplicationKind) bool {
	switch k {
	case ReplicationNone:
		return true
	case ReplicationLogical:
		return p == ReplicationPolicyLogical || p == ReplicationPolicyAll
	case ReplicationPhysical:
		return p == ReplicationPolicyAll
	}
	return false
}
