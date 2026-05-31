// Package store persists keyring blobs and public-key material to SQLite.
// The schema is intentionally tiny — this server is a blob-keyed-by-
// fingerprint store, not an application database.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/danass/pgp-sync/internal/model"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrVersionMismatch = errors.New("version mismatch")
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			fingerprint TEXT PRIMARY KEY NOT NULL,   -- uppercase hex, no spaces
			public_key  TEXT NOT NULL,               -- armored PGP public key (for sig verification)
			created_at  INTEGER NOT NULL,
			seen_at     INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS keyrings (
			fingerprint TEXT PRIMARY KEY NOT NULL REFERENCES users(fingerprint) ON DELETE CASCADE,
			version     INTEGER NOT NULL,
			ciphertext  BLOB NOT NULL,
			updated_at  INTEGER NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate %q: %w", q, err)
		}
	}
	return nil
}

// UpsertUser registers a fingerprint+public-key pair, or refreshes seen_at if
// already known. Returns true if this is the first time we've seen this user.
func (s *Store) UpsertUser(fingerprint, armoredPublicKey string) (created bool, err error) {
	now := time.Now().Unix()
	r := s.db.QueryRow(`SELECT 1 FROM users WHERE fingerprint = ?`, fingerprint)
	var dummy int
	switch err := r.Scan(&dummy); {
	case err == sql.ErrNoRows:
		_, err = s.db.Exec(`INSERT INTO users(fingerprint, public_key, created_at, seen_at) VALUES (?,?,?,?)`,
			fingerprint, armoredPublicKey, now, now)
		return true, err
	case err != nil:
		return false, err
	}
	_, err = s.db.Exec(`UPDATE users SET seen_at = ? WHERE fingerprint = ?`, now, fingerprint)
	return false, err
}

// GetPublicKey returns the armored public key we have on file for a user, or
// ErrNotFound if we don't know them yet.
func (s *Store) GetPublicKey(fingerprint string) (string, error) {
	var pk string
	err := s.db.QueryRow(`SELECT public_key FROM users WHERE fingerprint = ?`, fingerprint).Scan(&pk)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return pk, err
}

// GetKeyring returns the current keyring entry for fingerprint, or ErrNotFound.
func (s *Store) GetKeyring(fingerprint string) (model.KeyringEntry, error) {
	var e model.KeyringEntry
	e.Fingerprint = fingerprint
	err := s.db.QueryRow(`
		SELECT version, ciphertext, updated_at FROM keyrings WHERE fingerprint = ?
	`, fingerprint).Scan(&e.Version, &e.Ciphertext, &e.UpdatedAt)
	if err == sql.ErrNoRows {
		return e, ErrNotFound
	}
	return e, err
}

// PutKeyring inserts or updates the keyring for fingerprint. If prevVersion is
// non-zero, it must match the current stored version or ErrVersionMismatch is
// returned (optimistic concurrency). The new version is prevVersion+1 (or 1
// for a first write).
func (s *Store) PutKeyring(fingerprint string, prevVersion int64, ciphertext []byte) (model.KeyringEntry, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.KeyringEntry{}, err
	}
	defer tx.Rollback()

	var current sql.NullInt64
	err = tx.QueryRow(`SELECT version FROM keyrings WHERE fingerprint = ?`, fingerprint).Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return model.KeyringEntry{}, err
	}

	if current.Valid && current.Int64 != prevVersion {
		return model.KeyringEntry{}, ErrVersionMismatch
	}
	if !current.Valid && prevVersion != 0 {
		return model.KeyringEntry{}, ErrVersionMismatch
	}

	newVersion := prevVersion + 1
	now := time.Now().Unix()
	if current.Valid {
		if _, err := tx.Exec(`UPDATE keyrings SET version = ?, ciphertext = ?, updated_at = ? WHERE fingerprint = ?`,
			newVersion, ciphertext, now, fingerprint); err != nil {
			return model.KeyringEntry{}, err
		}
	} else {
		if _, err := tx.Exec(`INSERT INTO keyrings(fingerprint, version, ciphertext, updated_at) VALUES (?,?,?,?)`,
			fingerprint, newVersion, ciphertext, now); err != nil {
			return model.KeyringEntry{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.KeyringEntry{}, err
	}
	return model.KeyringEntry{
		Fingerprint: fingerprint,
		Version:     newVersion,
		Ciphertext:  ciphertext,
		UpdatedAt:   now,
	}, nil
}

// DeleteUser removes a user and their keyring (cascade).
func (s *Store) DeleteUser(fingerprint string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE fingerprint = ?`, fingerprint)
	return err
}
