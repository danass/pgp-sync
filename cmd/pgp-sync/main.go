// pgp-sync — a tiny, self-hostable end-to-end-encrypted sync server for PGP
// keyrings. The server holds opaque ciphertext blobs keyed by the user's PGP
// fingerprint and never sees plaintext. Authentication is by signing a
// server-issued random challenge with the user's PGP private key.
//
// See docs/PROTOCOL.md for the wire spec.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danass/pgp-sync/internal/server"
	"github.com/danass/pgp-sync/internal/store"
)

func main() {
	var (
		addr     = flag.String("addr", envOr("PGP_SYNC_ADDR", ":8443"), "listen address")
		dbPath   = flag.String("db", envOr("PGP_SYNC_DB", "/var/lib/pgp-sync/data.db"), "SQLite database path")
		certPath = flag.String("cert", envOr("PGP_SYNC_CERT", ""), "TLS certificate (fullchain). Empty = plain HTTP (use behind reverse proxy)")
		keyPath  = flag.String("key", envOr("PGP_SYNC_KEY", ""), "TLS private key")
		maxBlob  = flag.Int64("max-blob", 1<<20, "maximum encrypted blob size in bytes")
	)
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("store.Open(%q): %v", *dbPath, err)
	}
	defer st.Close()

	srv := server.New(st, server.Config{MaxBlobBytes: *maxBlob})
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Print("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	log.Printf("pgp-sync listening on %s (db=%s tls=%t)", *addr, *dbPath, *certPath != "")
	if *certPath != "" && *keyPath != "" {
		err = httpSrv.ListenAndServeTLS(*certPath, *keyPath)
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
