#!/bin/sh
# Runs inside the holistic-scan image: scans a target with agent-secret-scan,
# Betterleaks and TruffleHog and writes their reports to /out.
#   holistic-scan-run local /target     a mounted folder or file
#   holistic-scan-run remote URL        a git repository, cloned first
set -u

usage() {
  echo "usage: holistic-scan-run local PATH | remote URL" >&2
  exit 2
}
[ $# -eq 2 ] || usage
mode=$1
target=$2
out=/out
mkdir -p "$out" || exit 2

# Mounted repositories belong to another user; let git read them anyway.
export HOME=/tmp GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'

case $mode in
  local)
    [ -e "$target" ] || { echo "holistic-scan: $target does not exist" >&2; exit 2; }
    ;;
  remote)
    echo "holistic-scan: cloning $target" >&2
    # A mirror (every ref) as the .git of an empty work tree with an empty
    # index: TruffleHog needs both; nothing is checked out.
    GIT_TERMINAL_PROMPT=0 git clone --quiet --mirror -- "$target" /tmp/repo/.git || exit 2
    git -C /tmp/repo/.git config core.bare false || exit 2
    git -C /tmp/repo read-tree --empty || exit 2
    ;;
  *) usage ;;
esac

status=0
note() { # tool, exit code, findings
  case $2 in
    0 | 1) printf '  %-18s %s findings\n' "$1" "$3" ;;
    *) printf '  %-18s failed (exit %s)\n' "$1" "$2"; status=2 ;;
  esac
  [ "$3" = 0 ] || [ $status -eq 2 ] || status=1
}

echo "holistic-scan: agent-secret-scan" >&2
if [ "$mode" = local ]; then
  agent-secret-scan local "$target" --format jsonl -o "$out/agent-secret-scan.jsonl"
else
  agent-secret-scan git /tmp/repo --format jsonl -o "$out/agent-secret-scan.jsonl"
fi
ass=$?

echo "holistic-scan: betterleaks" >&2
if [ "$mode" = local ]; then
  betterleaks dir "$target" --redact --no-banner --no-color --report-format json --report-path "$out/betterleaks.json"
else
  betterleaks git /tmp/repo --log-opts=--all --redact --no-banner --no-color --report-format json --report-path "$out/betterleaks.json"
fi
bl=$?

# --no-verification: found credentials are not sent to their providers to test them.
echo "holistic-scan: trufflehog" >&2
if [ "$mode" = local ]; then
  trufflehog filesystem "$target" --json --no-update --no-verification > "$out/trufflehog.jsonl" 2> /tmp/trufflehog.log
else
  trufflehog git file:///tmp/repo --json --no-update --no-verification > "$out/trufflehog.jsonl" 2> /tmp/trufflehog.log
fi
th=$?
cat /tmp/trufflehog.log >&2
# TruffleHog's exit code does not tell findings from errors: 0 is success,
# anything else or an error in its log is a failed scan.
if [ $th -ne 0 ] || grep -q '"level":"error"' /tmp/trufflehog.log; then th=2; fi

count_lines() { [ -s "$1" ] && grep -c . "$1" || echo 0; }
echo
echo "holistic-scan results for ${HOLISTIC_SCAN_TARGET:-$target}"
note agent-secret-scan $ass "$(count_lines "$out/agent-secret-scan.jsonl")"
note betterleaks $bl "$( [ -s "$out/betterleaks.json" ] && jq length "$out/betterleaks.json" || echo 0)"
note trufflehog $th "$(count_lines "$out/trufflehog.jsonl")"
echo "  reports: agent-secret-scan.jsonl, betterleaks.json, trufflehog.jsonl"
exit $status
