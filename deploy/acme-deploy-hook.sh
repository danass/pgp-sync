#!/usr/bin/env bash
# acme.sh deploy hook for pgp-sync.
# Install with:
#   acme.sh --deploy -d baal.danpm.com --deploy-hook ./deploy/acme-deploy-hook.sh
#
# acme.sh calls this script with the following positional args after a
# successful issue/renew:
#   $1 = domain
#   $2 = private key path
#   $3 = fullchain path (used as the cert)
#   $4 = ca path
#   $5 = full cert chain (same as $3)

set -euo pipefail

DOMAIN="${1:-}"
KEY_PATH="${2:-}"
FULLCHAIN="${3:-${5:-}}"

if [[ -z "$DOMAIN" || -z "$KEY_PATH" || -z "$FULLCHAIN" ]]; then
  echo "usage: $0 <domain> <keypath> <fullchain>" >&2
  exit 1
fi

DEST=/etc/pgp-sync/certs
sudo install -d -m 0755 "$DEST"
sudo install -m 0644 "$FULLCHAIN" "$DEST/fullchain.pem"
sudo install -m 0640 "$KEY_PATH"  "$DEST/privkey.pem"
sudo chgrp pgpsync "$DEST/privkey.pem"

# Hot-reload the service to pick up the new cert.
sudo systemctl reload-or-restart pgp-sync.service

echo "pgp-sync: installed $DOMAIN cert and restarted service"
