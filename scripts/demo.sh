#!/bin/sh
# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
# Two realms (home.test, partner.test) and two fleets on one machine,
# plaintext peer links, everything under a temp dir. Ctrl-C leaves nothing.
set -e
D=$(mktemp -d /tmp/airc-demo.XXXXXX); H=$(cd "$(dirname "$0")/.." && pwd); U=$(id -u)
cat > $D/a.json <<J
{"realm":"home.test","client_unix":"$D/a.sock","peer_listen":"127.0.0.1:2482",
 "uid_namespaces":{"$U":["alice","carol"]},
 "peers":{"partner.test":{"host":"127.0.0.1","port":2492,"tls":false}},"spool_dir":"$D/a-spool"}
J
cat > $D/b.json <<J
{"realm":"partner.test","client_unix":"$D/b.sock","peer_listen":"127.0.0.1:2492",
 "namespaces":["support"],"trust_client_claims":true,
 "peers":{"home.test":{"host":"127.0.0.1","port":2482,"tls":false}},"spool_dir":"$D/b-spool"}
J
trap 'kill 0 2>/dev/null; rm -rf $D' EXIT INT TERM
$H/aircd -c $D/a.json 2>$D/a.log & $H/aircd -c $D/b.json 2>$D/b.log &
sleep 0.5
$H/airc --socket $D/a.sock listen carol/analyst &
$H/airc --socket $D/b.sock --claim-ns support listen support/desk &
sleep 0.5
export CO_SESSION_NAME=ops
$H/airc --socket $D/a.sock send carol/analyst "hello across fleets"
$H/airc --socket $D/a.sock send //partner.test/support/desk "hello across realms"
$H/airc --socket $D/a.sock send --from //partner.test/support/desk carol/analyst "spoof" || true
$H/airc --socket $D/a.sock send carol/nobody-yet "queued until someone binds it"
sleep 0.3; echo; echo "--- server A:"; $H/airc --socket $D/a.sock status
