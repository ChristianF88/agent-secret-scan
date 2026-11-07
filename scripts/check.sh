#!/usr/bin/env bash
# Quality gate. Used by the pre-commit hook and runnable by hand.
#   scripts/check.sh          fmt + clippy + tests + spec self-test
#   scripts/check.sh --quick  fmt + clippy only
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "cargo fmt --check"
cargo fmt --all --check

step "cargo clippy (-D warnings)"
cargo clippy --workspace --all-targets --locked -- -D warnings

[ "${1:-}" = "--quick" ] && exit 0

step "spec self-test (python)"
python3 spec/test_patterns.py

step "cargo test"
cargo test --workspace --locked --quiet

printf '\n\033[1;32mall checks passed\033[0m\n'
