#!/usr/bin/env bash
# Reproducible release build of the dvtee binary.
#
# The same source, toolchain and target give the same bytes, whatever the
# checkout path or user: paths are remapped, symbols stripped, and codegen is
# single-unit. CI builds twice from different directories and compares
# (.github/workflows/release.yml); anyone can rerun it and compare with the
# published SHA256SUMS.
#
#   scripts/build-release.sh [out-dir]
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-dist}
target=x86_64-unknown-linux-gnu
src=$(pwd)
cargo_home=${CARGO_HOME:-$HOME/.cargo}

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_DEBUG=false
export CARGO_PROFILE_RELEASE_INCREMENTAL=false
export RUSTFLAGS="--remap-path-prefix=$src=/build --remap-path-prefix=$cargo_home=/cargo -C link-arg=-Wl,--build-id=none"
unset RUSTC_WRAPPER

cargo build --locked --release --target "$target" --bin dvtee
mkdir -p "$out"
cp "${CARGO_TARGET_DIR:-target}/$target/release/dvtee" "$out/dvtee-$target"
(cd "$out" && sha256sum "dvtee-$target" | tee "dvtee-$target.sha256")
rustc --version >"$out/BUILD-TOOLCHAIN"
