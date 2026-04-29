# syntax=docker/dockerfile:1.7
#
# Build context: the workspace root, not this directory.
# Build with:  docker build -f swiyu-didtool/Dockerfile -t didtool .

FROM rust:1-alpine3.20 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# Workspace manifest plus both crates. swiyu-didtool depends on swiyu-core
# via a path dependency, so both must be present in the build context.
COPY Cargo.toml Cargo.lock ./
COPY swiyu-core swiyu-core
COPY swiyu-didtool swiyu-didtool

# Cache the cargo registry and target dir across builds. Cache mounts are
# not persisted into image layers, so the binary is copied out of the
# cached target dir before the RUN step ends.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p swiyu-didtool && \
    cp target/release/didtool /usr/local/bin/didtool

FROM alpine:3.20

RUN addgroup -S didtool && adduser -S -G didtool didtool

COPY --from=builder /usr/local/bin/didtool /usr/local/bin/didtool

ENV DIDTOOL_KEYSTORE=/data/keys \
    SWIYU_IDENTIFIER_REGISTRY_URL=https://identifier-reg-api.trust-infra.swiyu-int.admin.ch \
    SWIYU_TRUST_REGISTRY_URL=https://trust-reg.trust-infra.swiyu-int.admin.ch \
    SWIYU_TRUST_ISSUER_DID=did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212

RUN mkdir -p /data/keys && chown -R didtool:didtool /data

USER didtool
WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["didtool"]
CMD ["--help"]
