#!/usr/bin/env bash
# =============================================================================
# HTTP contract smoke test
# =============================================================================
# Exercises the running service the way a client would: probes, auth, scoping,
# versioning, method and size limits. It asserts status codes only — values are
# compared by length, never printed.
#
#   SECRETSD_ROOT_TOKEN=... SECRETSD_APP_TOKEN=... ./tests/smoke.sh
#
# Exit code is 0 only when every check passes.
set -uo pipefail

BASE="${BASE:-http://127.0.0.1:8200}"
ROOT="${SECRETSD_ROOT_TOKEN:?set SECRETSD_ROOT_TOKEN}"
APP="${SECRETSD_APP_TOKEN:-cg_mock_app_token_change_me}"

# Ubuntu images ship python3 only; a bare `python` silently produced empty
# expects, so resolve the interpreter once and name it explicitly.
PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  if command -v python3 >/dev/null 2>&1; then PYTHON=python3
  elif command -v python >/dev/null 2>&1; then PYTHON=python
  else echo "error: python3 is required" >&2; exit 2
  fi
fi

pass=0
fail=0

check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    printf '  PASS  %-44s %s\n' "$label" "$actual"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-44s expected %s, got %s\n' "$label" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"
}

json_field() {
  "$PYTHON" -c "import json,sys;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null
}

echo "target: $BASE"

# --- probes and authentication ----------------------------------------------
check "GET /healthz" 200 "$(code "$BASE/healthz")"
check "GET /readyz" 200 "$(code "$BASE/readyz")"
check "GET /v1/secrets without token" 401 "$(code "$BASE/v1/secrets")"
check "GET /v1/secrets with bad token" 401 "$(code -H 'Authorization: Bearer wrong-token' "$BASE/v1/secrets")"
check "GET /v1/secrets with app token (has list)" 200 "$(code -H "Authorization: Bearer $APP" "$BASE/v1/secrets")"

# --- write / read -----------------------------------------------------------
BODY='{"value":"smoke-test-value-not-a-credential"}'
check "PUT app/ci/smoke (root)" 201 \
  "$(code -X PUT -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' -d "$BODY" "$BASE/v1/secrets/app/ci/smoke")"
check "PUT again (version bump)" 201 \
  "$(code -X PUT -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' -d "$BODY" "$BASE/v1/secrets/app/ci/smoke")"

version="$(curl -s -H "Authorization: Bearer $ROOT" "$BASE/v1/secrets/app/ci/smoke" | json_field version)"
check "GET returns version 2" 2 "$version"

roundtrip="$(curl -s -H "Authorization: Bearer $ROOT" "$BASE/v1/secrets/app/ci/smoke" | "$PYTHON" -c '
import json, sys
value = json.load(sys.stdin).get("value", "")
print("match" if value == "smoke-test-value-not-a-credential" else "mismatch")
' 2>/dev/null)"
check "value round-trips exactly" match "$roundtrip"

# --- policy scoping ---------------------------------------------------------
check "app token reads app/ci/smoke" 200 "$(code -H "Authorization: Bearer $APP" "$BASE/v1/secrets/app/ci/smoke")"
check "app token denied app/admin/root" 403 "$(code -H "Authorization: Bearer $APP" "$BASE/v1/secrets/app/admin/root")"
check "app token denied write" 403 \
  "$(code -X PUT -H "Authorization: Bearer $APP" -H 'Content-Type: application/json' -d "$BODY" "$BASE/v1/secrets/app/ci/other")"
check "segment-aware prefix: app/ci-tokens denied" 403 "$(code -H "Authorization: Bearer $APP" "$BASE/v1/secrets/app/ci-tokens/x")"

# --- protocol edges ---------------------------------------------------------
check "POST /v1/secrets" 405 "$(code -X POST -H "Authorization: Bearer $ROOT" "$BASE/v1/secrets")"
check "HEAD /healthz" 200 "$(code -I "$BASE/healthz")"
check "GET /v1/status with app token" 200 "$(code -H "Authorization: Bearer $APP" "$BASE/v1/status")"
check "rotate denied for non-rotate token" 403 \
  "$(code -X POST -H "Authorization: Bearer $APP" -H 'Content-Type: application/json' -d '{"new_master_key":"x"}' "$BASE/v1/rotate")"
check "malformed JSON rejected" 400 \
  "$(code -X PUT -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' -d 'not-json' "$BASE/v1/secrets/app/ci/badjson")"
check "path traversal in name rejected" 400 \
  "$(code -X PUT -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' -d '{"value":"x"}' "$BASE/v1/secrets/app%2F..%2Fetc%2Fpasswd")"
check "non-string value rejected" 400 \
  "$(code -X PUT -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' -d '{"value":1234}' "$BASE/v1/secrets/app/ci/number")"
check "unknown secret" 404 "$(code -H "Authorization: Bearer $ROOT" "$BASE/v1/secrets/app/does-not-exist")"
check "rotation disabled by default" 403 \
  "$(code -X POST -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' \
    -d '{"new_master_key":"not-a-key"}' "$BASE/v1/rotate")"

big_file="$(mktemp)"
"$PYTHON" - "$big_file" <<'PY'
import sys
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write('{"value":"' + "A" * 70000 + '"}')
PY
check "oversized body rejected" 413 \
  "$(code -X PUT -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' --data-binary "@$big_file" "$BASE/v1/secrets/app/big")"
rm -f "$big_file"

# --- cleanup ----------------------------------------------------------------
check "DELETE with root" 200 "$(code -X DELETE -H "Authorization: Bearer $ROOT" "$BASE/v1/secrets/app/ci/smoke")"
check "deleted secret is gone" 404 "$(code -H "Authorization: Bearer $ROOT" "$BASE/v1/secrets/app/ci/smoke")"

echo
echo "summary: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
