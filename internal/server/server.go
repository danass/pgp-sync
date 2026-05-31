// Package server wires the HTTP routes for pgp-sync. It's intentionally tiny:
// the auth and storage logic live in their own packages; this layer is just
// JSON in / JSON out + CORS + body-size guards.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/danass/pgp-sync/internal/auth"
	"github.com/danass/pgp-sync/internal/store"
)

type Config struct {
	MaxBlobBytes int64
}

type Server struct {
	st  *store.Store
	cfg Config
	am  *auth.Manager
	mux *http.ServeMux
}

func New(st *store.Store, cfg Config) *Server {
	s := &Server{
		st:  st,
		cfg: cfg,
		am:  auth.NewManager(),
		mux: http.NewServeMux(),
	}
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/auth/challenge", s.handleChallenge)
	s.mux.HandleFunc("/v1/auth/respond", s.handleRespond)
	s.mux.HandleFunc("/v1/keyring", s.handleKeyring)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS — the addon talks to us from a `moz-extension://<uuid>` origin.
	// We don't bind to a specific UUID since the addon's identity is the PGP
	// signature, not the browser origin.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
	w.Header().Set("Vary", "Origin")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"time": time.Now().UTC().Format(time.RFC3339),
	})
}

// -- POST /v1/auth/challenge ---------------------------------------------------

type challengeReq struct {
	Fingerprint      string `json:"fingerprint"`        // uppercase hex, 40 chars
	PublicKeyArmored string `json:"public_key,omitempty"` // optional, on first contact
}
type challengeResp struct {
	Challenge string `json:"challenge"`  // hex bytes to sign
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req challengeReq
	if err := readJSON(r, 64*1024, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fp := strings.ToUpper(strings.ReplaceAll(req.Fingerprint, " ", ""))
	if len(fp) != 40 {
		writeError(w, http.StatusBadRequest, "fingerprint must be 40 hex chars")
		return
	}

	// If we don't have this fingerprint yet, the client must include their
	// armored public key on first contact. Otherwise we'd have no way to
	// verify the signature on /respond.
	if _, err := s.st.GetPublicKey(fp); errors.Is(err, store.ErrNotFound) {
		if req.PublicKeyArmored == "" {
			writeError(w, http.StatusBadRequest, "unknown fingerprint — include public_key on first challenge")
			return
		}
		gotFP, err := auth.FingerprintFromArmoredKey(req.PublicKeyArmored)
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not parse public_key: "+err.Error())
			return
		}
		if gotFP != fp {
			writeError(w, http.StatusBadRequest, "public_key fingerprint "+gotFP+" does not match requested "+fp)
			return
		}
		if _, err := s.st.UpsertUser(fp, req.PublicKeyArmored); err != nil {
			writeError(w, http.StatusInternalServerError, "store: "+err.Error())
			return
		}
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "store: "+err.Error())
		return
	}

	hex, exp, err := s.am.NewChallenge(fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rng: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, challengeResp{Challenge: hex, ExpiresAt: exp.Unix()})
}

// -- POST /v1/auth/respond -----------------------------------------------------

type respondReq struct {
	Challenge       string `json:"challenge"`
	SignatureArmored string `json:"signature"` // -----BEGIN PGP SIGNATURE-----
}
type respondResp struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func (s *Server) handleRespond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req respondReq
	if err := readJSON(r, 256*1024, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// We have to look up the public key from the bound fingerprint. The
	// challenge -> fingerprint map is held inside the auth.Manager (it set the
	// binding in handleChallenge), but we need to fetch the armored key from
	// the store to verify the signature.
	// To do this, we peek the binding: VerifyAndIssueToken needs the armored
	// key passed in.  We look it up here.
	fp, ok := s.am.PeekChallengeFingerprint(req.Challenge)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unknown or expired challenge")
		return
	}
	armored, err := s.st.GetPublicKey(fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store: "+err.Error())
		return
	}

	tok, exp, err := s.am.VerifyAndIssueToken(req.Challenge, req.SignatureArmored, armored)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, respondResp{Token: tok, ExpiresAt: exp.Unix()})
}

// -- /v1/keyring (GET, PUT) ----------------------------------------------------

type putReq struct {
	PrevVersion int64  `json:"prev_version"`
	Ciphertext  []byte `json:"ciphertext"` // base64-encoded by json
}
type entryResp struct {
	Fingerprint string `json:"fingerprint"`
	Version     int64  `json:"version"`
	Ciphertext  []byte `json:"ciphertext"`
	UpdatedAt   int64  `json:"updated_at"`
}

func (s *Server) handleKeyring(w http.ResponseWriter, r *http.Request) {
	fp, err := s.am.CheckBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	switch r.Method {
	case http.MethodGet:
		e, err := s.st.GetKeyring(fp)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusOK, entryResp{Fingerprint: fp, Version: 0})
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, entryResp{
			Fingerprint: e.Fingerprint, Version: e.Version,
			Ciphertext: e.Ciphertext, UpdatedAt: e.UpdatedAt,
		})
	case http.MethodPut:
		var req putReq
		if err := readJSON(r, s.cfg.MaxBlobBytes+64*1024, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if int64(len(req.Ciphertext)) > s.cfg.MaxBlobBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "ciphertext exceeds max")
			return
		}
		e, err := s.st.PutKeyring(fp, req.PrevVersion, req.Ciphertext)
		if errors.Is(err, store.ErrVersionMismatch) {
			writeError(w, http.StatusConflict, "version mismatch — pull first")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, entryResp{
			Fingerprint: e.Fingerprint, Version: e.Version,
			Ciphertext: e.Ciphertext, UpdatedAt: e.UpdatedAt,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "GET or PUT only")
	}
}

// -- helpers -------------------------------------------------------------------

func readJSON(r *http.Request, maxBytes int64, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Drain anything trailing so the connection can be reused cleanly.
	_, _ = io.Copy(io.Discard, r.Body)
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
