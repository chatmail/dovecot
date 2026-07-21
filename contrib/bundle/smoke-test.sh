#!/bin/bash
# Validate a built Dovecot bundle end to end, rootless-friendly but designed to
# run as root inside the CI container (so setuid to the mail user works).
#
#   contrib/bundle/smoke-test.sh [BUNDLE_DIR] [RUN_DIR]
#
# Proves: the bundle is self-contained (no host dovecot/libs), the master
# starts, the imap plugin closure (quota/zlib/last_login) dlopens cleanly, and
# an IMAP login + SELECT succeeds through the real dict passdb. LMTP delivery
# (notify/mail_lua/push_notification_lua) is attempted best-effort.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
bundle=${1:-/opt/dovecot}
run=${2:-$(mktemp -d)}
imapport=${IMAPPORT:-14300}
lmtpport=${LMTPPORT:-14324}
pidfile="$run/dovecot.pid"
fail=0

log()  { printf '== %s\n' "$*"; }
dump() { echo "---- dovecot.log ----"; cat "$run/dovecot.log" 2>/dev/null || true; echo "---------------------"; }

ensure_user() { id "$1" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$1"; }
if [ "$(id -u)" = 0 ]; then
  ensure_user vmail; ensure_user dovecot; ensure_user dovenull
else
  echo "WARN: not root; dovecot may fail to setuid. Prefer running as root." >&2
fi
vmailuid=$(id -u vmail)

log "prepare runtime under $run"
rm -rf "$run"; mkdir -p "$run/run" "$run/mail"
chown -R vmail:vmail "$run/mail" 2>/dev/null || true

render() { sed -e "s#@RUN@#$run#g" -e "s#@IMAPPORT@#$imapport#g" \
               -e "s#@LMTPPORT@#$lmtpport#g" -e "s#@VMAIL@#vmail#g" \
               -e "s#@VMAILUID@#$vmailuid#g" "$1"; }
render "$here/dovecot.conf.in"           > "$run/dovecot.conf"
render "$here/dovecot-dict-auth.conf.in" > "$run/dovecot-dict-auth.conf"
cp "$here/push_notification.lua" "$run/push_notification.lua"

# file dict: alternating key line / value line, JSON values (format = json).
# Dovecot namespaces dict keys with a "shared/" prefix, so the "passdb/%u" key
# in dovecot-dict-auth.conf is looked up as "shared/passdb/testuser" (confirmed
# via auth_debug). The stored keys must carry that prefix or every lookup misses.
cat > "$run/auth.dict" <<EOF
shared/passdb/testuser
{"password":"testpass"}
shared/userdb/testuser
{"uid":"$vmailuid","gid":"$vmailuid","home":"$run/mail/testuser"}
EOF
: > "$run/lastlogin.dict"
chmod 666 "$run/auth.dict" "$run/lastlogin.dict"

log "self-contained check (bundled libs resolve via extlib, not host dovecot)"
ldd "$bundle/sbin/dovecot" | sed 's/^/  /' || true
if readelf -d "$bundle/sbin/dovecot" | grep -q 'ORIGIN'; then
  echo "  RPATH uses \$ORIGIN: ok"
else
  echo "  WARN: no \$ORIGIN RPATH on sbin/dovecot"; fail=1
fi

log "start dovecot via launcher"
"$bundle/dovecot-bundle" -F -c "$run/dovecot.conf" >>"$run/dovecot.log" 2>&1 &
echo $! > "$pidfile"
cleanup() { [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true; }
trap cleanup EXIT

log "wait for imap port $imapport"
for i in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$imapport") 2>/dev/null; then break; fi
  sleep 0.2
  if ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then echo "dovecot exited early"; dump; exit 1; fi
done

log "IMAP login + SELECT INBOX via dict passdb (curl)"
if curl -sS --max-time 15 --url "imap://127.0.0.1:$imapport/INBOX" \
        --user "testuser:testpass" >/dev/null; then
  echo "  IMAP login + SELECT: ok"
else
  echo "  IMAP login FAILED"; fail=1
fi

log "check imap plugin closure loaded without dlopen errors"
if grep -Eiq 'dlopen|Can.t load|Fatal|Panic' "$run/dovecot.log"; then
  echo "  module/dlopen errors present:"; grep -Ei 'dlopen|Can.t load|Fatal|Panic' "$run/dovecot.log" | sed 's/^/    /'
  fail=1
else
  echo "  no dlopen/fatal errors: ok"
fi

log "LMTP delivery (best-effort: notify/mail_lua/push_notification_lua)"
if exec 3<>"/dev/tcp/127.0.0.1/$lmtpport" 2>/dev/null; then
  {
    printf 'LHLO test\r\n';                 sleep 0.3
    printf 'MAIL FROM:<s@test>\r\n';        sleep 0.3
    printf 'RCPT TO:<testuser>\r\n';        sleep 0.3
    printf 'DATA\r\n';                       sleep 0.3
    printf 'Subject: poc\r\n\r\nhello\r\n.\r\n'; sleep 0.5
    printf 'QUIT\r\n';                       sleep 0.3
  } >&3
  exec 3>&- || true
  sleep 0.5
  if find "$run/mail/testuser" -path '*/new/*' -type f 2>/dev/null | grep -q .; then
    echo "  LMTP delivery landed in maildir: ok"
  else
    echo "  LMTP delivery not confirmed (best-effort, non-fatal)"
  fi
else
  echo "  could not connect to LMTP (best-effort, non-fatal)"
fi

dump
if [ "$fail" = 0 ]; then echo "SMOKE TEST: PASS"; else echo "SMOKE TEST: FAIL"; fi
exit "$fail"
