#!/bin/bash
# Fixture self-test: every file in tests/expected.txt must reach at least its listed level
# (and clean/ files must stay CLEAN). Usage: tests/run.sh [path/to/php-verdict]
cd "$(dirname "$0")" || exit 2
BIN=${1:-../target/release/php-verdict}
[ -x "$BIN" ] || { echo "binary not found: $BIN (build first: cargo build --release)"; exit 2; }
rank() { case "$1" in CRITICAL) echo 3;; SUSPECT) echo 2;; WARN) echo 1;; *) echo 0;; esac; }
fail=0; n=0
while read -r f want; do
  case "$f" in ''|\#*) continue;; esac
  n=$((n+1))
  got=$("$BIN" --all "fixtures/$f" | awk '{print $1}')
  got=${got:-CLEAN}
  if [ "$want" = CLEAN ]; then ok=$([ "$got" = CLEAN ] && echo 1)
  else ok=$([ "$(rank "$got")" -ge "$(rank "$want")" ] && echo 1); fi
  if [ -n "$ok" ]; then printf 'ok    %-28s %s\n' "$f" "$got"
  else printf 'FAIL  %-28s got %s, want %s\n' "$f" "$got" "$want"; fail=$((fail+1)); fi
done < expected.txt
echo "$((n-fail))/$n passed"
[ "$fail" -eq 0 ]
