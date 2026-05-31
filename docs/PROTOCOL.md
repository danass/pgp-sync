# pgp-sync protocol — v1

`pgp-sync` is a tiny HTTP service for end-to-end-encrypted PGP keyring sync.
The server stores opaque ciphertext blobs keyed by a user's PGP fingerprint
and never sees plaintext.

The reference client is the [PGP for Firefox](https://addons.mozilla.org/en-GB/firefox/addon/pgp-for-firefox/)
addon — including the MV2 build for Tor Browser — but the protocol is
language- and client-agnostic. Anyone can implement a server or a client
against this spec.

## Trust model

- **Identity** = a PGP public key. Holders of the matching private key prove
  identity by signing a server-issued random challenge.
- **At-rest secrecy** = the server holds only ciphertext. Recommended client
  shape: PGP-encrypt the serialised keyring to its own public key. The
  protocol does not mandate this — any ciphertext the client can later
  decrypt works. The server cannot tell.
- **In-transit secrecy** = TLS, or run as a Tor hidden service.
- **Recoverability** = none beyond the PGP private key. Lose the key, lose
  access. Back up the private key out of band like a serious PGP user.

The server is therefore minimally trusted: it knows which fingerprints have
ever spoken to it, when, and the size of the ciphertext. It cannot read
keys, sign as you, or grant access to anyone who doesn't hold your private
key.

## Endpoints

Base URL: any HTTPS origin you control. The reference deployment lives at
`https://baal.danpm.com:8443`.

All request and response bodies are JSON. Byte fields (`ciphertext`,
`signature`) use standard base64 unless noted.

### `GET /healthz`

Liveness probe. Always 200 if the process is up.

```json
{ "ok": true, "time": "2026-05-31T02:06:18Z" }
```

### `POST /v1/auth/challenge`

Mint a one-shot challenge bound to a fingerprint.

Request:

```json
{
  "fingerprint": "7D6D036C2ED1E8ECA3133B5DXXXXXXXX",
  "public_key":  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----\n"
}
```

- `fingerprint`: 40 hex chars, uppercase, no spaces. The primary-key
  fingerprint of the PGP key proving identity.
- `public_key`: required **only on first contact**. The fingerprint inside
  the armored key must match `fingerprint` exactly; the server stores it for
  future signature verification.

Response (200):

```json
{
  "challenge":  "0a1b2c... (64 hex chars)",
  "expires_at": 1748674200
}
```

- `challenge`: 32 random bytes, hex-encoded. **Sign exactly these bytes**
  (not their hex string) as a detached PGP signature.
- `expires_at`: unix seconds. Currently 2 minutes after issue.

Errors:

| status | meaning |
|---|---|
| 400 | malformed fingerprint, missing `public_key` on first contact, or `public_key` fingerprint mismatch |
| 500 | server-side problem (storage, RNG) |

### `POST /v1/auth/respond`

Exchange a signed challenge for a bearer token.

Request:

```json
{
  "challenge": "0a1b2c...",
  "signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----\n"
}
```

- `signature`: an **armored detached signature** over the raw challenge
  bytes (the result of `hex.DecodeString(challenge)`), made by the private
  key matching the fingerprint bound to the challenge.

Response (200):

```json
{
  "token":      "abcdef... (64 hex chars)",
  "expires_at": 1748677800
}
```

- `token`: send as `Authorization: Bearer <token>` on subsequent calls.
- `expires_at`: currently 1 hour after issue.

Errors:

| status | meaning |
|---|---|
| 401 | unknown / expired challenge, or signature did not verify |

The challenge is consumed regardless of success — clients must re-request a
new challenge for a retry.

### `GET /v1/keyring`

Fetch the current keyring blob.

Headers:

```
Authorization: Bearer <token>
```

Response (200):

```json
{
  "fingerprint": "7D6D...",
  "version":     14,
  "ciphertext":  "<base64>",
  "updated_at":  1748670000
}
```

If the user has never uploaded a blob, the response still returns 200 with
`"version": 0` and `"ciphertext": null`. This lets the client distinguish
"first sync" from "auth failed".

Errors:

| status | meaning |
|---|---|
| 401 | missing / invalid bearer token |

### `PUT /v1/keyring`

Upload a new keyring blob.

Headers:

```
Authorization: Bearer <token>
Content-Type:  application/json
```

Request:

```json
{
  "prev_version": 14,
  "ciphertext":   "<base64>"
}
```

- `prev_version`: the version you most recently fetched, or `0` if you've
  never fetched. The server uses this for optimistic concurrency control —
  if the server's current version doesn't match, the write is rejected.
- `ciphertext`: opaque to the server. Default limit: 1 MiB.

Response (200):

```json
{
  "fingerprint": "7D6D...",
  "version":     15,
  "updated_at":  1748678400
}
```

`version` is `prev_version + 1`.

Errors:

| status | meaning |
|---|---|
| 401 | bad token |
| 409 | version mismatch (someone else wrote — pull first, merge, retry) |
| 413 | ciphertext exceeds server limit |

## CORS

The reference server sets `Access-Control-Allow-Origin: *`. This is safe
because authentication is by PGP signature, not by browser origin. A custom
server can lock CORS down to specific origins if desired.

## Reference flows

### First sync from a fresh device

```
client                                   server
  | POST /v1/auth/challenge                  |
  |   { fingerprint, public_key }            |
  |----------------------------------------->|
  |<--- { challenge, expires_at }            |
  |                                          |
  | sign(challenge bytes, private key)       |
  |                                          |
  | POST /v1/auth/respond                    |
  |   { challenge, signature }               |
  |----------------------------------------->|
  |<--- { token, expires_at }                |
  |                                          |
  | GET /v1/keyring  (Authorization: Bearer) |
  |----------------------------------------->|
  |<--- { version: 0 }    (no blob yet)      |
  |                                          |
  | encrypt local keyring to own key         |
  | PUT /v1/keyring                          |
  |   { prev_version: 0, ciphertext }        |
  |----------------------------------------->|
  |<--- { version: 1 }                       |
```

### Concurrent write detection

```
device A: GET → version 14
device B: GET → version 14
device A: PUT prev=14 → server now 15
device B: PUT prev=14 → 409 conflict
device B: GET → version 15
device B: merge locally
device B: PUT prev=15 → server now 16
```

The merge step is client-side and out of scope for this spec — the reference
client uses fingerprint as the merge key and keeps the most recently updated
copy of each.

## Versions

- **v1** (this document) — challenge/respond auth, single keyring blob per
  user, optimistic concurrency by integer version.

Breaking changes will live under `/v2/...` so old clients keep working.

## Out of scope (deliberately)

- Multi-user sharing. This is a single-user sync, not a team keyring.
- Server-side search / filtering. The server only sees ciphertext.
- Push notifications. Clients poll on demand or on user action.
- Recovery flows. Lose the PGP private key, lose access.
