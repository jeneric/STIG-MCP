#!/usr/bin/env bash
# Helpers for .github/workflows/tls-proxy.yml, run under bash on Linux, macOS and Windows (Git Bash).
set -euo pipefail

PORT=18080

make_ca() {  # make_ca DIR COMMON_NAME BASIC_CONSTRAINTS
  local dir=$1 cn=$2 constraints=$3
  mkdir -p "$dir"
  cat > "$dir/ca.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $cn
[ext]
basicConstraints = $constraints
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$dir/ca.cnf" \
    -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
  # mitmdump reads its CA from confdir/mitmproxy-ca.pem, private key first.
  cat "$dir/key.pem" "$dir/cert.pem" > "$dir/mitmproxy-ca.pem"
}

make_cas() {  # make_cas DIR
  make_ca "$1/untrusted" "stig-mcp untrusted test CA" "critical, CA:TRUE"
  make_ca "$1/compliant" "stig-mcp compliant test CA" "critical, CA:TRUE"
  # Python 3.13+ sets VERIFY_X509_STRICT, which rejects a CA whose basicConstraints is not critical.
  make_ca "$1/strict" "stig-mcp strict-mode test CA" "CA:TRUE"
}

trust() {  # trust CERT
  case "$(uname -s)" in
    Linux)
      sudo cp "$1" "/usr/local/share/ca-certificates/$(basename "$(dirname "$1")")-test-ca.crt"
      sudo update-ca-certificates ;;
    Darwin)
      # Without this, adding trust settings waits for a password dialog no runner can answer.
      sudo security authorizationdb write com.apple.trust-settings.admin allow
      sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$1" ;;
    MINGW* | MSYS*)
      certutil -addstore -f Root "$(cygpath -w "$1")" ;;
    *)
      echo "tls_ci.sh trust: no store recipe for $(uname -s)" >&2
      exit 2 ;;
  esac
}

with_proxy() {  # with_proxy CONFDIR CMD...
  local confdir=$1
  shift
  local bin
  bin=$(uv tool dir --bin)
  # On Windows, uv prints a native path; Git Bash needs its own form, and the .exe is implied.
  if command -v cygpath >/dev/null; then bin=$(cygpath -u "$bin"); fi
  "$bin/mitmdump" -q --listen-host 127.0.0.1 --listen-port "$PORT" --set confdir="$confdir" &
  # Global, not local: the EXIT trap runs after this function's locals are gone.
  PROXY_PID=$!
  trap 'kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true' EXIT
  local ready=no
  for _ in $(seq 150); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then ready=yes; break; fi
    sleep 0.2
  done
  if [ "$ready" != yes ]; then
    echo "tls_ci.sh with-proxy: mitmdump never listened on 127.0.0.1:$PORT" >&2
    exit 2
  fi
  HTTPS_PROXY="http://127.0.0.1:$PORT" HTTP_PROXY="http://127.0.0.1:$PORT" "$@"
}

expect_fail() {  # expect_fail CMD...: succeed only when CMD fails on a certificate error
  local output
  if output=$("$@" 2>&1); then
    echo "$output"
    echo "tls_ci.sh expect-fail: expected a certificate failure, but the command succeeded" >&2
    exit 1
  fi
  echo "$output"
  if ! grep -qiE "invalid peer certificate|UnknownIssuer|unknown ?issuer|CERTIFICATE_VERIFY_FAILED|The TLS connection to [^ ]+ failed" <<<"$output"; then
    echo "tls_ci.sh expect-fail: the command failed, but not on a certificate error" >&2
    exit 1
  fi
}

command=${1:-}
shift || true
case "$command" in
  make-cas) make_cas "$@" ;;
  trust) trust "$@" ;;
  with-proxy) with_proxy "$@" ;;
  expect-fail) expect_fail "$@" ;;
  *)
    echo "usage: tls_ci.sh make-cas DIR | trust CERT | with-proxy CONFDIR CMD... | expect-fail CMD..." >&2
    exit 2 ;;
esac
