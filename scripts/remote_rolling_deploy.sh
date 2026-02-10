#!/usr/bin/env bash
set -euo pipefail

BIN_SOURCE="${1:-}"
if [[ -z "$BIN_SOURCE" ]]; then
  echo "usage: $0 <path-to-new-binary>" >&2
  exit 1
fi

if [[ ! -f "$BIN_SOURCE" ]]; then
  echo "binary not found: $BIN_SOURCE" >&2
  exit 1
fi

BIN_DST="/usr/local/bin/identity-server"
INSTANCES=(a b)

instance_port() {
  local instance="$1"
  local env_file="/etc/identity-registry/${instance}.env"

  if [[ -f "$env_file" ]]; then
    local port
    port="$(grep -E '^PORT=' "$env_file" | tail -n1 | cut -d'=' -f2 || true)"
    if [[ -n "$port" ]]; then
      echo "$port"
      return 0
    fi
  fi

  case "$instance" in
    a) echo 8081 ;;
    b) echo 8082 ;;
    *) echo "unknown instance: $instance" >&2; return 1 ;;
  esac
}

wait_for_health() {
  local url="$1"
  local attempts=45
  local i
  for ((i=1; i<=attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "health check failed for $url" >&2
  return 1
}

sudo install -Dm755 "$BIN_SOURCE" "${BIN_DST}.new"
sudo mv "${BIN_DST}.new" "$BIN_DST"

for instance in "${INSTANCES[@]}"; do
  local_port="$(instance_port "$instance")"
  health_url="http://127.0.0.1:${local_port}/health"

  echo "Restarting identity-registry@${instance}"
  sudo systemctl restart "identity-registry@${instance}"
  if ! wait_for_health "$health_url"; then
    echo "identity-registry@${instance} failed health check; service status:"
    sudo systemctl status "identity-registry@${instance}" --no-pager -l || true
    exit 1
  fi
  echo "identity-registry@${instance} healthy on :${local_port}"
done

echo "Rolling deployment complete"
