# Build the swiyu-issuer-web front end as a single runtime image: the
# Angular SPA's static assets are served by the axum BFF, which also
# exposes `/api` and proxies to the mgmtapi over the network. One process,
# one port — the mgmtapi and registries live elsewhere and are reached via
# the BFF's env-configured URLs.
#
# The build context must be the *workspace root* (one directory up from
# this file) because the BFF depends on the sibling crates swiyu-core and
# swiyu-registries via `path = "../..."`:
#
#   docker build -f swiyu-issuer-web/Dockerfile -t swiyu-issuer-web:dev .

# ---- SPA build ----------------------------------------------------------
FROM node:22-bookworm-slim AS spa-builder
WORKDIR /spa
# Copy manifests first so `npm ci` is cached unless dependencies change.
COPY swiyu-issuer-web/spa/package.json swiyu-issuer-web/spa/package-lock.json ./
RUN npm ci
COPY swiyu-issuer-web/spa/ ./
RUN npm run build

# ---- BFF build ----------------------------------------------------------
# Mirrors swiyu-issuer/Dockerfile: cargo-chef caches dependency compilation,
# and `-bookworm` keeps the builder's glibc in sync with the slim runtime.
ARG RUST_TAG=latest-rust-1-bookworm
FROM lukemathwalker/cargo-chef:${RUST_TAG} AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# The workspace `.cargo/config.toml` selects clang + mold as the linker.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang mold \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p swiyu-issuer-web-bff

# ---- Runtime ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 issuer
COPY --from=builder    /app/target/release/swiyu-issuer-web-bff /usr/local/bin/swiyu-issuer-web-bff
COPY --from=spa-builder /spa/dist/spa/browser                   /srv/spa
USER issuer
EXPOSE 3000
ENV BFF_PORT=3000 \
    SPA_DIR=/srv/spa
# MGMTAPI_URL, MGMTAPI_TOKEN and IDENTIFIER_REGISTRY_URL must be supplied at
# run time; they point at the separately deployed mgmtapi and registries.
ENTRYPOINT ["/usr/local/bin/swiyu-issuer-web-bff"]
LABEL org.opencontainers.image.title="swiyu-issuer-web" \
      org.opencontainers.image.description="SWIYU issuer — web front end (SPA + BFF)" \
      org.opencontainers.image.source="https://github.com/Gubaer/swiyu-rs" \
      org.opencontainers.image.url="https://github.com/Gubaer/swiyu-rs" \
      org.opencontainers.image.documentation="https://github.com/Gubaer/swiyu-rs/tree/master/swiyu-issuer-web" \
      org.opencontainers.image.vendor="Gubaer" \
      org.opencontainers.image.licenses="MIT"
