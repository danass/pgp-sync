# pgp-sync

A tiny, self-hostable, end-to-end-encrypted **PGP keyring sync server**.

You run an instance. Your clients (or your friends') talk to it over HTTPS or
a Tor `.onion`. The server holds only ciphertext — it can't read your keys,
sign as you, or grant access to anyone who doesn't hold your PGP private key.

The reference client is **[PGP for Firefox](https://addons.mozilla.org/en-GB/firefox/addon/pgp-for-firefox/)**
on Mozilla Add-ons — a local-first PGP toolkit (keyring, notepad,
page-scanner) for Firefox and Tor Browser. The addon talks to a pgp-sync
server of your choice; you keep custody of both the keys and the storage.

## Design in one screen

```
┌──────────────┐                  ┌──────────────────┐
│  PGP for FF  │   opaque blob    │  pgp-sync        │
│  addon       │ ───────────────► │  (your VPS, RPi, │
│              │ ◄─────────────── │   .onion, …)     │
│  PGP key     │   opaque blob    │                  │
└──────────────┘                  └──────────────────┘
       │                                  │
       │ encrypts/decrypts                │ stores ciphertext
       │ to its own public key            │ keyed by fingerprint
       ▼                                  ▼
   plaintext keyring               { fingerprint → encrypted blob }
```

- **Identity** = a PGP public key. Holders prove identity by signing a
  random challenge.
- **Storage** = opaque ciphertext keyed by primary-key fingerprint. The
  server learns nothing about the contents.
- **Auth** = challenge/response with PGP signatures. Short-lived bearer
  tokens for follow-up requests.
- **Versioning** = monotonic integer with optimistic concurrency. If two
  devices write simultaneously the loser gets a 409 and pulls/merges.

Full wire spec: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Why it exists

PGP key management on multiple devices is a perennial pain. Existing
solutions force you to either:
- Trust a third party (key escrow, Proton, etc.) — defeats the point of
  end-to-end crypto.
- Manage rsync / Syncthing / USB sticks yourself — works, but no version
  semantics and easy to silently overwrite.

pgp-sync is a ~400-line Go server that handles only the boring half of the
problem — opaque blob storage with versioning — and does it carefully. All
encryption stays on the client. Your private key never touches the server.
The server is throwaway: wipe it and you lose nothing that matters (your
keyring is still on every device that had it).

## Run your own

### Quick: a Linux box you control

```sh
git clone https://github.com/danass/pgp-sync
cd pgp-sync
cp .env.example .env
$EDITOR .env                              # set DOMAIN, PORT, paths
./scripts/build-linux.sh                  # cross-compiles a static binary
scp -r . your-server:/tmp/pgp-sync-staging/
ssh your-server '
  cd /tmp/pgp-sync-staging
  sudo ./scripts/install.sh
'
```

What `.env` controls (defaults in parens):

- `DOMAIN` (`sync.example.com`) — the hostname your TLS cert is for.
- `PORT` (`8443`) — listening port; unprivileged user so > 1024.
- `DATA_DIR` (`/var/lib/pgp-sync`) — where SQLite lives.
- `CERT_DIR` (`/etc/pgp-sync/certs`) — where acme.sh deposits the cert.
- `SERVICE_USER` (`pgpsync`) — Unix user the service runs as.

The installer creates the service user, lays down `/opt/pgp-sync`,
`/etc/pgp-sync`, the data dir, renders a `systemd` unit from those values,
generates `/etc/pgp-sync/env` for the binary, and starts the service.

Then wire up TLS via the included acme.sh deploy hook (assumes acme.sh is
already managing your cert):

```sh
~/.acme.sh/acme.sh --deploy \
  -d "$DOMAIN" \
  --deploy-hook /tmp/pgp-sync-staging/deploy/acme-deploy-hook.sh
```

That copies the live cert into `$CERT_DIR` and bounces the service.
Renewals trigger the hook automatically.

### Docker

```sh
docker build -t pgp-sync -f deploy/docker/Dockerfile .
docker run -d --name pgp-sync \
  -p 8443:8443 \
  -v $PWD/data:/var/lib/pgp-sync \
  -v $PWD/certs:/etc/pgp-sync/certs:ro \
  -e PGP_SYNC_CERT=/etc/pgp-sync/certs/fullchain.pem \
  -e PGP_SYNC_KEY=/etc/pgp-sync/certs/privkey.pem \
  pgp-sync
```

### As a Tor hidden service

Append [deploy/tor/torrc.sample](deploy/tor/torrc.sample) to `/etc/tor/torrc`,
`systemctl reload tor`, read `/var/lib/tor/pgp-sync/hostname`, point your
addon at `http://<that>.onion`. No inbound port forwarding needed — outbound
Tor connection initiated by `tor`.

The `.onion` already provides authenticated encryption; running TLS on top
is redundant. Set `PGP_SYNC_CERT=""` in the env file to disable built-in
TLS and let the service serve plain HTTP on `127.0.0.1:8443`, which tor
will then expose.

## Configure the addon to use your server

1. Install the [PGP for Firefox addon from AMO](https://addons.mozilla.org/en-GB/firefox/addon/pgp-for-firefox/),
   or load it manually via `about:debugging#/runtime/this-firefox`.
2. In the addon → **Keyring** → **Sync** section.
3. Enter your server's base URL — e.g. `https://sync.example.com:8443` or
   `http://abcdef…onion`.
4. Pick your primary PGP key (the one you'll authenticate as).
5. Click **Push** for the first sync. From then on, every keyring change
   syncs automatically.

## Threat model

What pgp-sync protects against:

- Casual server compromise: attacker steals the SQLite db → gets opaque
  ciphertext + fingerprints + timestamps. No plaintext keys.
- Network attacker on the path: TLS or `.onion`.
- Server impersonation: client-side signature verification on the
  downloaded blob (it's PGP-encrypted to you; only your key decrypts).

What it does NOT protect against:

- A malicious server *deleting* your blob or serving an old version
  (rollback). Mitigation: clients track local version and warn on
  rollback. (Reference client implements this.)
- An attacker who compromises your PGP private key. There is no recovery
  from that — by design. Back up your private key.
- Metadata collection: a server operator can see which fingerprints sync
  when, the size of each blob, and the IP/Tor circuit you connect from.

## Hacking on it

```
.
├── cmd/pgp-sync/         # entrypoint
├── internal/
│   ├── auth/             # challenge/response + token mgmt
│   ├── model/            # shared types
│   ├── server/           # HTTP handlers
│   └── store/            # SQLite-backed persistence
├── docs/PROTOCOL.md      # wire spec — implement your own client/server
├── deploy/
│   ├── systemd/          # service unit + env sample
│   ├── docker/           # multi-stage Dockerfile
│   ├── tor/              # torrc sample for .onion deployment
│   └── acme-deploy-hook.sh
└── scripts/
    ├── build-linux.sh    # cross-compile to linux/amd64
    └── install.sh        # one-shot installer (Debian/Ubuntu)
```

Local dev:

```sh
go run ./cmd/pgp-sync -addr :8443 -db /tmp/pgp-sync-dev.db
```

Run with plain HTTP for local testing — leave `-cert` and `-key` empty.

## License

MIT for the server. See [LICENSE](LICENSE).

The reference client ([PGP for Firefox](https://addons.mozilla.org/en-GB/firefox/addon/pgp-for-firefox/))
has its own license. Bundled OpenPGP.js in the client is LGPL-3.0.
