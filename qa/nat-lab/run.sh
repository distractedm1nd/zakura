#!/usr/bin/env bash
set -euo pipefail
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$lab_dir/../.." && pwd)"
cd "$repo_dir"
result_dir="${1:-$lab_dir/results/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$result_dir"
result_dir="$(cd -- "$result_dir" && pwd)"
cargo build --locked --target-dir "$lab_dir/target" --manifest-path "$lab_dir/Cargo.toml"
cargo build --locked --target-dir "$lab_dir/relay/target" --manifest-path "$lab_dir/relay/Cargo.toml"
export ZAKURA_NAT_RELAY="$lab_dir/relay/target/debug/zakura-nat-relay"
git rev-parse HEAD > "$result_dir/revision.txt"
"$lab_dir/target/debug/zakura-nat-lab" "$result_dir" 2> "$result_dir/lab.log" | tee "$result_dir/results.jsonl"
