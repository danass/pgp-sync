// Package model holds the shared types crossing layer boundaries.
package model

// KeyringEntry is what the server stores per user. The Ciphertext field is
// opaque to the server — it's whatever the client uploaded (recommended
// shape: PGP-encrypted-to-self armor).
type KeyringEntry struct {
	Fingerprint string `json:"fingerprint"`
	Version     int64  `json:"version"`
	Ciphertext  []byte `json:"ciphertext"`
	UpdatedAt   int64  `json:"updated_at"` // unix seconds
}
