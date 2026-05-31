// Package auth handles the challenge/response PGP signature auth flow and
// short-lived bearer tokens. The challenges, tokens, and their fingerprint
// bindings live in memory only — losing them is a non-event (client just
// re-auths).
package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const (
	ChallengeBytes = 32
	ChallengeTTL   = 2 * time.Minute
	TokenTTL       = 60 * time.Minute
	TokenBytes     = 32
)

var (
	ErrUnknownChallenge = errors.New("unknown or expired challenge")
	ErrBadSignature     = errors.New("signature does not match expected public key")
	ErrUnknownToken     = errors.New("unknown or expired token")
	ErrBadKey           = errors.New("could not parse public key")
)

type challenge struct {
	bytes       []byte
	fingerprint string
	expires     time.Time
}

type token struct {
	fingerprint string
	expires     time.Time
}

type Manager struct {
	mu         sync.Mutex
	challenges map[string]challenge // key = hex(challenge bytes)
	tokens     map[string]token     // key = hex(token bytes)
}

func NewManager() *Manager {
	m := &Manager{
		challenges: make(map[string]challenge),
		tokens:     make(map[string]token),
	}
	go m.sweep()
	return m
}

func (m *Manager) sweep() {
	for range time.Tick(30 * time.Second) {
		m.mu.Lock()
		now := time.Now()
		for k, c := range m.challenges {
			if c.expires.Before(now) {
				delete(m.challenges, k)
			}
		}
		for k, t := range m.tokens {
			if t.expires.Before(now) {
				delete(m.tokens, k)
			}
		}
		m.mu.Unlock()
	}
}

// NewChallenge mints a random challenge bound to a fingerprint. The hex string
// returned IS the challenge — clients sign exactly these bytes.
func (m *Manager) NewChallenge(fingerprint string) (string, time.Time, error) {
	buf := make([]byte, ChallengeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	hexStr := hex.EncodeToString(buf)
	exp := time.Now().Add(ChallengeTTL)
	m.mu.Lock()
	m.challenges[hexStr] = challenge{
		bytes:       buf,
		fingerprint: strings.ToUpper(fingerprint),
		expires:     exp,
	}
	m.mu.Unlock()
	return hexStr, exp, nil
}

// VerifyAndIssueToken consumes a challenge by verifying that signedArmored is a
// detached signature over the challenge bytes, made by the holder of the
// private half of publicKeyArmored. On success it returns a fresh bearer token
// and its expiry, and removes the challenge (one-shot).
func (m *Manager) VerifyAndIssueToken(challengeHex string, signedArmored string, publicKeyArmored string) (string, time.Time, error) {
	m.mu.Lock()
	c, ok := m.challenges[challengeHex]
	if ok && c.expires.Before(time.Now()) {
		delete(m.challenges, challengeHex)
		ok = false
	}
	if !ok {
		m.mu.Unlock()
		return "", time.Time{}, ErrUnknownChallenge
	}
	delete(m.challenges, challengeHex)
	m.mu.Unlock()

	// Parse the public key.
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicKeyArmored))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %v", ErrBadKey, err)
	}

	// Confirm the key's fingerprint matches what we have on file.
	matched := false
	for _, entity := range keyring {
		fp := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
		if fp == c.fingerprint {
			matched = true
			break
		}
	}
	if !matched {
		return "", time.Time{}, fmt.Errorf("%w: provided key does not match expected fingerprint %s", ErrBadKey, c.fingerprint)
	}

	// Verify the detached signature over the raw challenge bytes.
	sigBlock, err := armor.Decode(strings.NewReader(signedArmored))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("decode signature armor: %w", err)
	}
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(c.bytes), sigBlock.Body, nil); err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	// Mint token.
	tbuf := make([]byte, TokenBytes)
	if _, err := rand.Read(tbuf); err != nil {
		return "", time.Time{}, err
	}
	tokHex := hex.EncodeToString(tbuf)
	exp := time.Now().Add(TokenTTL)
	m.mu.Lock()
	m.tokens[tokHex] = token{fingerprint: c.fingerprint, expires: exp}
	m.mu.Unlock()
	return tokHex, exp, nil
}

// PeekChallengeFingerprint returns the fingerprint bound to a not-yet-consumed
// challenge, or ok=false if the challenge is unknown or expired. The challenge
// is *not* consumed — call VerifyAndIssueToken to actually use it.
func (m *Manager) PeekChallengeFingerprint(challengeHex string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[challengeHex]
	if !ok || c.expires.Before(time.Now()) {
		return "", false
	}
	return c.fingerprint, true
}

// CheckToken returns the bound fingerprint if the token is valid, else error.
func (m *Manager) CheckToken(tokHex string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[tokHex]
	if !ok || t.expires.Before(time.Now()) {
		return "", ErrUnknownToken
	}
	return t.fingerprint, nil
}

// CheckBearer parses an "Authorization: Bearer <hex>" value and returns the
// fingerprint bound to it. Uses constant-time comparison on the token bytes
// to avoid timing-leaking valid tokens via the map lookup pattern.
func (m *Manager) CheckBearer(authHeader string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", ErrUnknownToken
	}
	provided := strings.TrimSpace(authHeader[len(prefix):])
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, t := range m.tokens {
		if subtle.ConstantTimeCompare([]byte(k), []byte(provided)) == 1 {
			if t.expires.Before(now) {
				return "", ErrUnknownToken
			}
			return t.fingerprint, nil
		}
	}
	return "", ErrUnknownToken
}

// FingerprintFromArmoredKey returns the uppercase hex primary-key fingerprint
// of the first entity in an armored PGP key block.
func FingerprintFromArmoredKey(armored string) (string, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil || len(keyring) == 0 {
		return "", ErrBadKey
	}
	return strings.ToUpper(hex.EncodeToString(keyring[0].PrimaryKey.Fingerprint)), nil
}
