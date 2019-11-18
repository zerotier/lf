package lf

// PointerTTL is the global TTL for pointers (one year).
// After this time nodes may purge or refuse to replicate pointers.
const PointerTTL = 31536000

// Pointer is a small ephemeral value that can be attached to a record.
// It must be signed by a public key that is embedded in the record and is
// part of the record value's clear text region (not masked). Pointers are
// ephemeral, not guaranteed to be stored for longer than a set maximum TTL,
// and are replicated using a best-effort replication algorithm. They are
// not a part of the DAG.
type Pointer struct {
	// RecordIDPrefix is the first 64 bits of the ID of this pointer's identity record containing its public key.
	// The ID is either a hash of the record's selectors or its hash if it has none. If multiple records
	// have this same ID prefix (collisions are possible) this is disambiguated by seeing which record's
	// embedded key successfully verifies this pointer's signature.
	RecordIDPrefix [8]byte

	// PublicKeyIndex is the index of the public key in this record's value.
	PublicKeyIndex uint

	// PublicKeyType is the algorithm used for this pointer's signatures.
	PublicKeyType byte

	// Timestamp in SECONDS since epoch.
	Timestamp uint64

	// Value is the current value of this pointer.
	Value []byte

	// Signature of this pointer with the identity record's public key.
	Signature []byte

	// WorkAlgorithm is the type of the Work field.
	WorkAlgorithm byte

	// Work to "pay" for this pointer.
	Work []byte
}
