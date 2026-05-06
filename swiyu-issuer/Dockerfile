# Build the swiyu-issuer binaries (`issuer-mgmt` and `issuer-oidc`)
# as release images, using cargo-chef to keep dependency compilation
# in a cached layer.
#
# The build context must be the *workspace root* (one directory up
# from this file) because swiyu-issuer depends on the sibling crates
# swiyu-core and swiyu-registries via `path = "../..."`. Compose
# wires this up with `context: ..` and `dockerfile: swiyu-issuer/Dockerfile`.
#
# The Dockerfile produces two runtime images via separate `runtime-*`
# stages, selected with Docker's `--target` flag:
#
#   docker build -f swiyu-issuer/Dockerfile --target runtime-mgmt \
#       -t swiyu-issuer-mgmt:dev .
#   docker build -f swiyu-issuer/Dockerfile --target runtime-oidc \
#       -t swiyu-issuer-oidc:dev .
#
# The compose file uses the same flag per service.

# `-bookworm` keeps the builder's glibc in sync with the
# `debian:bookworm-slim` runtime stage. Mismatching variants (e.g.
# the default `latest-rust-1` is trixie-based) link the binary
# against a newer glibc than the runtime provides and the container
# fails to start with `GLIBC_2.38 not found`.
ARG RUST_TAG=latest-rust-1-bookworm
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
RUN cargo build --release --bin issuer-mgmt --bin issuer-oidc -p swiyu-issuer

FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --uid 10001 issuer

FROM runtime-base AS runtime-mgmt
COPY --from=builder /app/target/release/issuer-mgmt /usr/local/bin/issuer-mgmt
USER issuer
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/issuer-mgmt"]

FROM runtime-base AS runtime-oidc
COPY --from=builder /app/target/release/issuer-oidc /usr/local/bin/issuer-oidc
USER issuer
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/issuer-oidc"]
