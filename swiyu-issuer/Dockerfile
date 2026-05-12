# Build the swiyu-issuer binaries (`swiyu-issuer-mgmtapi`,
# `swiyu-issuer-oidcapi`, and `swiyu-issuer-cli`) as release images,
# using cargo-chef to keep dependency compilation in a cached layer.
#
# The build context must be the *workspace root* (one directory up
# from this file) because swiyu-issuer depends on the sibling crates
# swiyu-core and swiyu-registries via `path = "../..."`. Compose
# wires this up with `context: ..` and `dockerfile: swiyu-issuer/Dockerfile`.
#
# The Dockerfile produces three runtime images via separate `runtime-*`
# stages, selected with Docker's `--target` flag:
#
#   docker build -f swiyu-issuer/Dockerfile --target runtime-mgmtapi \
#       -t swiyu-issuer-mgmtapi:dev .
#   docker build -f swiyu-issuer/Dockerfile --target runtime-oidcapi \
#       -t swiyu-issuer-oidcapi:dev .
#   docker build -f swiyu-issuer/Dockerfile --target runtime-cli \
#       -t swiyu-issuer-cli:dev .
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
# The workspace `.cargo/config.toml` selects clang + mold as the
# linker. Install both so the cargo-chef builder image can honour
# that configuration; without them the build fails with
# `linker `clang` not found`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang mold \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
# Build only third-party dependencies. This layer is reused unless
# Cargo.lock or any crate's Cargo.toml changes.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin swiyu-issuer-mgmtapi --bin swiyu-issuer-oidcapi --bin swiyu-issuer-cli -p swiyu-issuer

FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --uid 10001 issuer

FROM runtime-base AS runtime-mgmtapi
COPY --from=builder /app/target/release/swiyu-issuer-mgmtapi /usr/local/bin/swiyu-issuer-mgmtapi
USER issuer
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/swiyu-issuer-mgmtapi"]

FROM runtime-base AS runtime-oidcapi
COPY --from=builder /app/target/release/swiyu-issuer-oidcapi /usr/local/bin/swiyu-issuer-oidcapi
USER issuer
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/swiyu-issuer-oidcapi"]

# Operator/dev-loop CLI. Used by the bootstrap-dev-tenant compose
# service to seed the dev tenant's oauth_refresh_token from .env on
# every `docker compose up`. Has no long-running entrypoint —
# invocations come from the compose service or `docker run` with
# explicit subcommand args.
FROM runtime-base AS runtime-cli
COPY --from=builder /app/target/release/swiyu-issuer-cli /usr/local/bin/swiyu-issuer-cli
USER issuer
ENTRYPOINT ["/usr/local/bin/swiyu-issuer-cli"]
