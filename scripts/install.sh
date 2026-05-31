#!/usr/bin/env bash
# One-shot installer for pgp-sync on a Debian/Ubuntu box (tested on baal:
# Debian 13, systemd 257). Idempotent — safe to re-run after upgrades.
#
# Run from inside this repo on the target host:
#   sudo ./scripts/install.sh
#
# Expects a freshly-built binary at ./bin/pgp-sync-linux-amd64. The
# build-linux.sh script cross-compiles one from a Go toolchain.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo $0)" >&2
  exit 1
fi

BIN_SRC="${BIN_SRC:-$(cd "$(dirname "$0")/.." && pwd)/bin/pgp-sync-linux-amd64}"
if [[ ! -x "$BIN_SRC" ]]; then
  echo "Missing binary: $BIN_SRC" >&2
  echo "Build it first with: ./scripts/build-linux.sh" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 1. Service user.
if ! id -u pgpsync >/dev/null 2>&1; then
  echo "==> creating pgpsync user"
  useradd --system --no-create-home --shell /usr/sbin/nologin pgpsync
fi

# 2. Directories.
install -d -m 0755 -o root      -g root      /opt/pgp-sync
install -d -m 0755 -o root      -g root      /etc/pgp-sync
install -d -m 0750 -o pgpsync   -g pgpsync   /etc/pgp-sync/certs
install -d -m 0750 -o pgpsync   -g pgpsync   /var/lib/pgp-sync

# 3. Binary.
install -m 0755 "$BIN_SRC" /opt/pgp-sync/pgp-sync

# 4. systemd unit.
install -m 0644 "$REPO_ROOT/deploy/systemd/pgp-sync.service" /etc/systemd/system/pgp-sync.service

# 5. Environment file — only seed it if missing, so re-runs don't clobber.
if [[ ! -f /etc/pgp-sync/env ]]; then
  install -m 0644 "$REPO_ROOT/deploy/systemd/env.sample" /etc/pgp-sync/env
  echo "==> seeded /etc/pgp-sync/env from env.sample (edit if needed)"
fi

# 6. Pick up unit changes and start / restart.
systemctl daemon-reload
systemctl enable pgp-sync.service
systemctl restart pgp-sync.service

echo
echo "==> pgp-sync installed."
echo "    status: systemctl status pgp-sync"
echo "    logs:   journalctl -u pgp-sync -f"
echo
echo "Next: wire up TLS via acme.sh:"
echo "    acme.sh --deploy -d baal.danpm.com --deploy-hook $REPO_ROOT/deploy/acme-deploy-hook.sh"
