# Development image. A TEE deployment bakes the binary into the measured,
# dm-verity protected guest image instead (see ../ROADMAP.md).
FROM rust:1-bookworm@sha256:7085845219c18e7c5b1f34ed9ce89b84f822f2e3d54a02774cedc996ac0f304f AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY certs ./certs
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/dvtee /usr/local/bin/dvtee
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/dvtee"]
CMD ["serve"]
