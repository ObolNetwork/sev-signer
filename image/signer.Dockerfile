# Builds the dvtee binary for the guest image (image/build.sh).
#
# glibc, statically linked, so one binary runs in the initrd, in the root and
# on the host (for verify-evidence). Every input is pinned: the toolchain
# image by digest (Rust 1.100.0) and the crates by Cargo.lock. Fixed paths
# (/src, /cargo) keep the paths rustc embeds identical across hosts.
FROM rust:1.100.0-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2

ENV CARGO_HOME=/cargo \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="-C target-feature=+crt-static"
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY certs ./certs
RUN cargo build --release --locked --target x86_64-unknown-linux-gnu \
 && cp target/x86_64-unknown-linux-gnu/release/dvtee /dvtee \
 && ldd /dvtee 2>&1 | grep -qE 'statically linked|not a dynamic executable'
