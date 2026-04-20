#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "$script_dir/../../../.." && pwd)"
cd "$project_root"

usage() {
  echo "Usage: $0 <native|direct|blob|wrapper|script-path> [extra forge args...]"
}

classify_script() {
  local name
  name="$(basename "$1")"
  case "$name" in
    WhirBlobNativeTxBenchmark*.s.sol)
      mode="native"
      target_contract=()
      ;;
    WhirTxBenchmark*.s.sol)
      mode="direct"
      target_contract=()
      ;;
    WhirBlobTxBenchmark*.s.sol)
      mode="blob"
      target_contract=()
      ;;
    MeasureTxGas*.s.sol)
      mode="wrapper"
      target_contract=(--tc MeasureTxGas)
      ;;
    *)
      echo "Unknown benchmark script: $1"
      exit 1
      ;;
  esac
}

discover_script_for_mode() {
  local pattern
  case "$1" in
    native) pattern="WhirBlobNativeTxBenchmark*.s.sol" ;;
    direct) pattern="WhirTxBenchmark*.s.sol" ;;
    blob) pattern="WhirBlobTxBenchmark*.s.sol" ;;
    wrapper) pattern="MeasureTxGas*.s.sol" ;;
    *)
      usage
      exit 1
      ;;
  esac

  mapfile -t matches < <(find script -maxdepth 1 -type f -name "$pattern" | sort)
  if [[ ${#matches[@]} -eq 0 ]]; then
    echo "No benchmark script matched mode '$1'."
    exit 1
  fi
  if [[ ${#matches[@]} -gt 1 ]]; then
    echo "Mode '$1' is ambiguous on this branch. Pass an explicit script path instead."
    printf 'Matches:\n'
    printf '  %s\n' "${matches[@]}"
    exit 1
  fi

  script_path="${matches[0]}"
  classify_script "$script_path"
}

raw_target="${1:-}"
if [[ -z "$raw_target" ]]; then
  usage
  exit 1
fi
shift

mode=""
script_path=""
target_contract=()

if [[ -f "$raw_target" ]]; then
  script_path="$raw_target"
  classify_script "$script_path"
elif [[ -f "$project_root/$raw_target" ]]; then
  script_path="$raw_target"
  classify_script "$script_path"
elif [[ "$raw_target" == *.s.sol || "$raw_target" == */* ]]; then
  echo "Benchmark script not found: $raw_target"
  exit 1
else
  discover_script_for_mode "$raw_target"
fi

rpc_url="${RPC_URL:-http://127.0.0.1:8545}"
private_key="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

forge script "$script_path" \
  --rpc-url "$rpc_url" \
  --broadcast \
  --slow \
  --private-key "$private_key" \
  "${target_contract[@]}" \
  "$@"

python3 "$script_dir/parse_tx_gas.py" "$script_path"
