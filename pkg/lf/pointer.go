package lf

// Pointer is a small ephemeral value that can be attached to a record.
// Records with pointers must have a nil masking key (meaning the owner of the record
// is actually used). The format of the value is not specified. Instead the index
// of the key for a given signature algorithm is included in the pointer and the
// pointer is checked against this key.
type Pointer struct {
	// RecordIDPrefix is the first 64 bits of the ID of this pointer's identity record containing its public key.
	// The ID is either a hash of the record's selectors or its hash if it has none.
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

	// Work to "pay" for this pointer.
	Work []byte

	// WorkAlgorithm is the type of the Work field.
	WorkAlgorithm byte
}
