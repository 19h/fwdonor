#!/usr/bin/env bash
# Sync the source to the server, build there, and restart the service once
# nobody is in the middle of a donation.
#   ./deploy.sh [root@int]
#
#   IDLE_SECS  quiet time required before restarting (default 10)
#   MAX_WAIT   give up waiting after this many seconds and restart anyway
#              (default 0: wait as long as it takes)
#   FRONTEND_ONLY  rebuild and swap dist/ only, without a restart (the server
#              reads it per request). Only for page changes that need nothing
#              new from the server.
set -euo pipefail
cd -- "$(dirname -- "$0")"
host=${1:-root@int}
remote=/data/fwdonor

rsync -a --no-owner --no-group --delete \
  --exclude /target/ --exclude /pow-wasm/target/ --exclude /vendor/ --exclude /dist/ --exclude /dist.next/ --exclude /dist.old/ \
  --exclude /runtime/ --exclude /spool/ --exclude /bulk/ --exclude /firmwares/ \
  --exclude /tdlib/ --exclude /tdlib-source/ --exclude /tdlib-build/ --exclude /fwdonor.toml --exclude '/fwdonor.toml.*' \
  --exclude /.git/ --exclude node_modules/ --exclude .DS_Store --exclude /tdlib-build.log --exclude /build.log \
  ./ "$host:$remote/"

if [ -n "${FRONTEND_ONLY:-}" ]; then
  ssh "$host" bash -s <<EOF
set -euo pipefail
export PATH="\$HOME/.cargo/bin:\$PATH"
cd $remote
SKIP_CARGO=1 scripts/build.sh
EOF
  exit 0
fi

ssh "$host" IDLE_SECS="${IDLE_SECS:-10}" MAX_WAIT="${MAX_WAIT:-0}" bash -s <<EOF
set -euo pipefail
export PATH="\$HOME/.cargo/bin:\$PATH"
cd $remote
[ -f fwdonor.toml ] || install -m 644 deploy/fwdonor.toml fwdonor.toml
# The running service keeps serving the old dist/ while this builds.
STAGE_DIST=1 scripts/build.sh
install -d -o fwdonor -g fwdonor -m 700 runtime spool bulk firmwares
install -m 644 deploy/fwdonor.service /etc/systemd/system/fwdonor.service
systemctl daemon-reload

swap_dist() {
  rm -rf dist.old
  if [ -d dist ]; then mv dist dist.old; fi
  mv dist.next dist
}

if ! grep -q '"bot_token": "' runtime/telegram.json 2>/dev/null; then
  swap_dist
  rm -rf dist.old
  echo "bot not logged in yet: run 'fwdonor login' first (see README)"
  exit 0
fi

if systemctl is-active --quiet fwdonor; then
  # Wait until no upload is receiving, verifying, queued or posting, and no
  # donor has talked to the server for IDLE_SECS (older builds have no
  # idle_secs: then the counters must stay at zero for IDLE_SECS instead).
  python3 - <<'PY'
import json, os, time, urllib.request
need = int(os.environ['IDLE_SECS'])
max_wait = int(os.environ['MAX_WAIT'])
start = time.monotonic()
quiet_since = None
reported = -1e9
while True:
    now = time.monotonic()
    try:
        h = json.load(urllib.request.urlopen('http://127.0.0.1:18090/api/health', timeout=3))
    except Exception as e:
        print(f'health check failed ({e}); restarting now')
        break
    busy = h.get('queued', 0) or h.get('active', 0) or h.get('spooled_bytes', 0)
    idle = h.get('idle_secs')
    if busy:
        quiet_since = None
    elif idle is not None:
        if idle >= need:
            break
    else:
        quiet_since = quiet_since or now
        if now - quiet_since >= need:
            break
    if max_wait and now - start >= max_wait:
        print(f'still busy after {max_wait}s; restarting anyway (pages retry by themselves)')
        break
    if now - reported >= 30:
        reported = now
        print(f'waiting for a quiet moment: {h.get("active", "?")} active, {h.get("queued", 0)} queued, '
              f'idle {idle if idle is not None else "?"}s, {h.get("posted")} posted so far', flush=True)
    time.sleep(0.5)
print(f'quiet after {time.monotonic() - start:.0f}s', flush=True)
PY
fi

# The server keeps accepting pages built against the zrax revision it
# replaces (runtime/zrax-revs.json). Servers from before that file existed
# didn't record theirs: ask the running one.
if [ ! -f runtime/zrax-revs.json ] &&
   running_rev=\$(curl -fsS --max-time 3 http://127.0.0.1:18090/api/policy |
     python3 -c 'import json, sys; print(json.load(sys.stdin)["zrax_rev"])'); then
  printf '[{"rev": "%s", "since": %s}]\n' "\$running_rev" "\$(date +%s)" > runtime/zrax-revs.json
  chown fwdonor:fwdonor runtime/zrax-revs.json
  chmod 600 runtime/zrax-revs.json
fi

swap_dist
systemctl enable fwdonor >/dev/null 2>&1
systemctl restart fwdonor
rm -rf dist.old
for _ in \$(seq 1 60); do
  if curl -fsS --max-time 2 http://127.0.0.1:18090/api/health >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS --max-time 2 http://127.0.0.1:18090/api/health && echo
systemctl --no-pager --lines=5 status fwdonor || true
EOF
