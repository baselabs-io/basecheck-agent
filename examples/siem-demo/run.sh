#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/basecheck-siem-demo.XXXXXX")"

cd "$root"
go run ./examples/siem-demo/fixture -path "$demo_dir/demo.sqlite"
go build -o "$demo_dir/receiver-demo" ./examples/siem-demo/receiver
sed \
  -e "s|CONTROL_SETS_PATH|$root/control-sets|" \
  -e "s|DATABASE_PATH|$demo_dir/demo.sqlite|" \
  examples/siem-demo/config.yaml > "$demo_dir/config.yaml"
"$demo_dir/receiver-demo" > "$demo_dir/events.jsonl" 2>&1 &
receiver_pid=$!
trap 'kill "$receiver_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  if curl -fs http://127.0.0.1:8787/health >/dev/null; then
    ready=true
    break
  fi
  sleep 0.1
done

if [ "${ready:-false}" != true ]; then
  cat "$demo_dir/events.jsonl"
  exit 1
fi

(cd "$demo_dir" && "$root/basecheck-agent" --config config.yaml)

echo
echo "Received events:"
cat "$demo_dir/events.jsonl"
echo "Demo files: $demo_dir"
