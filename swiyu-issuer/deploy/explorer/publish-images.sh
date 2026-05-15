#!/usr/bin/env bash
# Build the swiyu-issuer Docker images and optionally push to GHCR.
#
# Local tags applied to every build, per image:
#   swiyu-issuer-<name>:swiyu-beta
#   swiyu-issuer-<name>:<version>-swiyu-beta
# With --push, also tags as <REGISTRY>/swiyu-issuer-<name>:... and pushes both.
#
# Env vars:
#   REGISTRY   defaults to ghcr.io/gubaer; override for a fork.
#   PLATFORMS  defaults to linux/amd64; set e.g. linux/amd64,linux/arm64 for multi-arch.
#
# Other arguments are forwarded to `docker buildx build` (e.g. --no-cache).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISSUER_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${ISSUER_DIR}/.." && pwd)"

VERSION="$(grep -m1 '^version' "${ISSUER_DIR}/Cargo.toml" \
    | sed -E 's/^version *= *"([^"]+)".*/\1/')"

REGISTRY="${REGISTRY:-ghcr.io/gubaer}"
PLATFORMS="${PLATFORMS:-linux/amd64}"

# Dynamic OCI labels — describe the build, not the source tree. The static
# org.opencontainers.image.* labels live in the Dockerfile per runtime stage.
# `set -e` aborts the script if `git rev-parse HEAD` fails (e.g. run outside a
# checkout), so no label-less image is ever produced.
GIT_REVISION="$(git rev-parse HEAD)"
BUILD_CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PUSH=0
DOCKER_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --push) PUSH=1 ;;
        *) DOCKER_ARGS+=("$arg") ;;
    esac
done

if ! docker buildx version >/dev/null 2>&1; then
    echo "error: 'docker buildx' is not available. Install Docker 19.03+ with the buildx plugin." >&2
    exit 1
fi

if ! docker buildx inspect >/dev/null 2>&1; then
    echo "error: no usable buildx builder for platforms '${PLATFORMS}'." >&2
    echo "       create one with: docker buildx create --use" >&2
    exit 1
fi

if [[ "${PUSH}" -eq 1 ]] && ! command -v jq >/dev/null 2>&1; then
    echo "error: 'jq' is required with --push to extract image digests." >&2
    exit 1
fi

STAGES=(mgmtapi oidcapi cli)

cd "${REPO_ROOT}"

PUSHED_REFS=()

for stage in "${STAGES[@]}"; do
    image_name="swiyu-issuer-${stage}"
    target="runtime-${stage}"

    # buildx pushes every -t when --push is set, so on a push run we use
    # only the ${REGISTRY}/-prefixed names. Unprefixed local-only tags
    # would otherwise resolve to docker.io/library/<name> and fail with
    # "push access denied". Dry runs (--load) keep the local-only tags
    # so the images can be used from the local docker daemon directly.
    if [[ "${PUSH}" -eq 1 ]]; then
        TAGS=(
            -t "${REGISTRY}/${image_name}:swiyu-beta"
            -t "${REGISTRY}/${image_name}:${VERSION}-swiyu-beta"
        )
    else
        TAGS=(
            -t "${image_name}:swiyu-beta"
            -t "${image_name}:${VERSION}-swiyu-beta"
        )
    fi

    LABELS=(
        --label "org.opencontainers.image.version=${VERSION}"
        --label "org.opencontainers.image.revision=${GIT_REVISION}"
        --label "org.opencontainers.image.created=${BUILD_CREATED}"
    )

    # Registry cache is only used alongside --push. Without --push there's no
    # cache to import from (nothing was ever pushed) and trying logs a noisy
    # buildx ERROR. Local buildkit cache handles repeat dry runs.
    CACHE_ARGS=()
    if [[ "${PUSH}" -eq 1 ]]; then
        CACHE_ARGS+=(
            --cache-from "type=registry,ref=${REGISTRY}/${image_name}:buildcache"
            --cache-to "type=registry,ref=${REGISTRY}/${image_name}:buildcache,mode=max"
        )
    fi

    metadata_file=""
    EXTRA_ARGS=()
    if [[ "${PUSH}" -eq 1 ]]; then
        metadata_file="$(mktemp)"
        EXTRA_ARGS+=(--push --metadata-file "${metadata_file}")
    else
        EXTRA_ARGS+=(--load)
    fi

    echo "==> Building ${image_name} (target ${target}, platforms ${PLATFORMS})"
    docker buildx build \
        -f swiyu-issuer/Dockerfile \
        --target "${target}" \
        --platform "${PLATFORMS}" \
        "${TAGS[@]}" \
        "${LABELS[@]}" \
        "${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"}" \
        "${EXTRA_ARGS[@]}" \
        "${DOCKER_ARGS[@]+"${DOCKER_ARGS[@]}"}" \
        .

    if [[ "${PUSH}" -eq 1 ]]; then
        digest="$(jq -r '."containerimage.digest"' "${metadata_file}")"
        rm -f "${metadata_file}"
        PUSHED_REFS+=("${REGISTRY}/${image_name}@${digest}")
    fi
done

if [[ "${PUSH}" -eq 1 ]]; then
    echo
    echo "Pushed images:"
    for ref in "${PUSHED_REFS[@]}"; do
        echo "  ${ref}"
    done
fi
