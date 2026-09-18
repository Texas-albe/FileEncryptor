#!/usr/bin/env bash
# Build the fe_age static library for Linux (x86_64) and copy it next to this script.
# Requires: Rust toolchain with the x86_64-unknown-linux-gnu target, and the C
#           toolchain (gcc/clang) used to build FileEncryptorCLI.
#
# Usage:
#   cd /path/to/FileEncryptor/age-ffi
#   ./build-linux.sh
#
# Builds the `age` crate (dependency at E:/rage/age) and the FFI crate (this
# folder, a member of the E:/rage workspace).

set -euo pipefail

RUST_TARGET="x86_64-unknown-linux-gnu"
# For other arches change the target, e.g. aarch64-unknown-linux-gnu.

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/lib/linux"
mkdir -p "$OUT_DIR"

echo "Building fe_age for ${RUST_TARGET} ..."
# Build from the rage workspace so age's workspace dependencies resolve.
( cd "$WORKSPACE_ROOT" && cargo build --release -p fe_age --target "$RUST_TARGET" )

LIB_SRC="$WORKSPACE_ROOT/target/${RUST_TARGET}/release/libfe_age.a"
[ -f "$LIB_SRC" ] || { echo "Expected library not found: $LIB_SRC" >&2; exit 1; }

cp -f "$LIB_SRC" "$OUT_DIR/"
echo "Copied libfe_age.a -> $OUT_DIR"
echo "Done. The CLI CMake will find it via WITH_AGE (default ON)."
