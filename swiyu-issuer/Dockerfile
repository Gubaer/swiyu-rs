# Build the swiyu-issuer `issuer-mgmt` binary as a release image,
# using cargo-chef to keep dependency compilation in a cached layer.
#
# The build context must be the *workspace root* (one directory up
# from this file) because swiyu-issuer depends on the sibling crates
# swiyu-core and swiyu-registries via `path = "../..."`. Compose
# wires this up with `context: ..` and `dockerfile: swiyu-issuer/Dockerfile`.
#
# To build by hand:
#   docker build -f swiyu-issuer/Dockerfile -t swiyu-issuer-mgmt:dev .

ARG RUST_TAG=latest-rust-1
FROM lukemathwalker/cargo-chef:${RUST_TAG} AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build only third-party dependencies. This layer is reused unless
# Cargo.lock or any crate's Cargo.toml changes.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin issuer-mgmt -p swiyu-issuer

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --uid 10001 issuer
COPY --from=builder /app/target/release/issuer-mgmt /usr/local/bin/issuer-mgmt
USER issuer
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/issuer-mgmt"]
