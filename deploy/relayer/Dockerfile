# QShield relayer image (build context: repository root).
#   docker build -f deploy/relayer/Dockerfile -t qshield-relayer .
# The relayer holds one Ed25519 fee-payer key, supplied at runtime through
# QSHIELD_RELAYER_KEYPAIR_JSON (never baked into the image).

FROM rust:1-slim-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . .
# rust-toolchain.toml pins the compiler; rustup installs it here.
RUN cargo build --locked --release -p qshield-relayer && strip target/release/qshield-relayer

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home relayer
COPY --from=build /src/target/release/qshield-relayer /usr/local/bin/qshield-relayer
USER relayer
ENV QSHIELD_RELAYER_BIND=0.0.0.0:8787
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/qshield-relayer"]
# Behind Fly's proxy: rate-limit by the address it appends to X-Forwarded-For.
CMD ["--trust-proxy", "--http-threads", "8", "--max-proposal-hours", "168", "--rate-limit", "20"]
