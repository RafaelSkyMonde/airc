#!/bin/sh
# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
# Install or upgrade the AIRC realm server on this host. Idempotent; run with sudo.
#
#   sudo scripts/install.sh <realm> [fleet-user ...]
#
#   <realm> is the DNS name this server answers for; each fleet-user is a Unix account whose
#   agents form a fleet (its uid becomes the namespace of the same name). Only used when the
#   config is first created.
#
# What it does:
#   - system account `airc` (no fleet of its own, no shell)
#   - /opt/airc            a copy of aircd, airc and scripts/airc  (re-copied on every run)
#   - /etc/airc/aircd.json config, created from aircd.example.json ONLY if absent
#   - /var/lib/airc/spool  the spool, owned by airc
#   - /etc/systemd/system/aircd.service, enabled and (re)started
# Fleet relays are per-owner user units: see airc-relay.service in this directory.
set -e
REALM="${1:?usage: install.sh <realm> [fleet-user ...]}"
shift
FLEETS="$*"
HERE=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
# Work from /: tools such as find return to the starting directory, and a caller standing in a
# stale network mount (sshfs, NFS) would otherwise make them fail or hang.
cd /
step() { echo "install: $*"; }
step "source $HERE, realm $REALM"

step "system account airc"
getent passwd airc >/dev/null || useradd --system --home-dir /var/lib/airc --shell /usr/sbin/nologin airc
step "directories /opt/airc /etc/airc /var/lib/airc"
install -d -m 755 /opt/airc /etc/airc
install -d -m 755 -o airc -g airc /var/lib/airc
install -d -m 750 -o airc -g airc /var/lib/airc/spool
chmod 644 /var/lib/airc/events.jsonl 2>/dev/null || true
step "copying the package to /opt/airc"
rm -rf /opt/airc/airc.d.tmp
cp -r "$HERE/scripts/airc" /opt/airc/airc.d.tmp
find /opt/airc/airc.d.tmp -name __pycache__ -prune -exec rm -rf {} +
rm -rf /opt/airc/airc.pkg && mv /opt/airc/airc.d.tmp /opt/airc/airc.pkg
# launchers look for the package next to themselves as ./scripts/airc; give them that layout
install -d /opt/airc/scripts
rm -rf /opt/airc/scripts/airc && mv /opt/airc/airc.pkg /opt/airc/scripts/airc
install -m 755 "$HERE/aircd" "$HERE/airc" /opt/airc/
step "config /etc/airc/aircd.json"
if [ ! -f /etc/airc/aircd.json ]; then
  python3 - "$REALM" $FLEETS > /etc/airc/aircd.json <<'PY'
import json, sys, pwd
cfg = {
  "_comment": "AIRC realm server. uid_namespaces: fleet owner uid -> namespace(s). peer_listen/tls stay unset until peer authentication exists.",
  "realm": sys.argv[1],
  "client_unix": "/run/airc/airc.sock",
  "client_unix_mode": "666",
  "uid_namespaces": {},
  "peers": {},
  "spool_dir": "/var/lib/airc/spool",
  "policy": {"default_allow": False, "rules": [
    {"from": "*", "to": f"//{sys.argv[1]}/_resolver", "allow": True, "note": "health check is public"},
  ]},
}
for name in sys.argv[2:]:
    try:
        cfg["uid_namespaces"][str(pwd.getpwnam(name).pw_uid)] = [name]
    except KeyError:
        continue
    fleet = f"//{sys.argv[1]}/{name}/**"
    cfg["policy"]["rules"].append({"from": fleet, "to": fleet, "allow": True, "note": f"{name}'s agents talk among themselves"})
cfg["policy"]["rules"] += [
    {"links": True, "note": "links and passports decide here"},
    {"from": "*", "to": "*", "allow": False, "note": "everything else needs a link or a passport"},
]
print(json.dumps(cfg, indent=2))
PY
  chmod 644 /etc/airc/aircd.json
  echo "wrote /etc/airc/aircd.json"
fi
step "systemd unit aircd.service"
install -m 644 "$HERE/scripts/aircd.service" /etc/systemd/system/aircd.service
systemctl daemon-reload
systemctl enable --now aircd.service
step "restarting aircd (open streams close first; this can take up to the unit's stop timeout)"
systemctl restart aircd.service
sleep 0.5
systemctl --no-pager --lines=3 status aircd.service || true
echo "installed: /opt/airc  config: /etc/airc/aircd.json  socket: /run/airc/airc.sock"
