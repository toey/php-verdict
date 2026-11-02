#!/bin/bash
# php-verdict installer: build from source, self-test, back up whatever is installed, then swap in atomically.
#
#   ./install.sh                       build + test + install to /usr/local/bin/php-verdict
#   ./install.sh --dest PATH           install to another path
#   ./install.sh --honeypot            install to /opt/honeypot/php-verdict-rs (the path the honeypot scanners call)
#   ./install.sh --install-rust        install a Rust toolchain with rustup first if cargo is missing
#   ./install.sh --rollback [--dest P] put the newest backup back
set -euo pipefail

DEST=/usr/local/bin/php-verdict
HONEYPOT_TREE=/opt/honeypot/php-verdict-rs
HONEYPOT=0 INSTALL_RUST=0 ROLLBACK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dest) DEST=$2; shift ;;
    --honeypot) HONEYPOT=1; DEST=$HONEYPOT_TREE/target/release/php-verdict ;;
    --install-rust) INSTALL_RUST=1 ;;
    --rollback) ROLLBACK=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
  shift
done
SRC=$(cd "$(dirname "$0")" && pwd)

if [ "$ROLLBACK" = 1 ]; then
  bak=$(ls -t "$DEST".bak-* 2>/dev/null | head -1 || true)
  [ -n "$bak" ] || { echo "no backup next to $DEST"; exit 1; }
  cp -p "$bak" "$DEST.new" && mv "$DEST.new" "$DEST"
  echo "rolled back: $bak -> $DEST"; exit 0
fi

# -- toolchain
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
  if [ "$INSTALL_RUST" = 1 ]; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    echo "cargo not found. Install Rust (rerun with --install-rust, or see https://rustup.rs)"; exit 1
  fi
fi
echo "toolchain: $(rustc --version)"   # needs >= 1.85 (edition 2024)

# -- build (low priority: this is usually run on a busy web server)
cd "$SRC"
nice -n 10 cargo build --release
BIN=$SRC/target/release/php-verdict

# -- self-test before touching anything installed
bash "$SRC/tests/run.sh" "$BIN"

# -- install: backup, copy beside the target, rename into place (scanners never see a half-written file)
mkdir -p "$(dirname "$DEST")"
if [ -f "$DEST" ]; then
  if cmp -s "$BIN" "$DEST"; then echo "already installed: $DEST is identical"; exit 0; fi
  cp -p "$DEST" "$DEST.bak-$(date +%Y%m%d-%H%M%S)"
fi
cp "$BIN" "$DEST.new" && chmod 755 "$DEST.new" && mv "$DEST.new" "$DEST"

if [ "$HONEYPOT" = 1 ]; then
  # keep the source tree the scanners are built from in step with the binary
  [ -d "$HONEYPOT_TREE/src" ] && cp -a "$HONEYPOT_TREE/src" "$HONEYPOT_TREE/src.bak-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$HONEYPOT_TREE/src"
  cp "$SRC"/src/*.rs "$HONEYPOT_TREE/src/"
  cp "$SRC/Cargo.toml" "$SRC/Cargo.lock" "$HONEYPOT_TREE/"
fi

echo "installed: $DEST ($(md5sum "$DEST" | cut -c1-12))"
echo "rollback:  $0 --rollback --dest $DEST"
