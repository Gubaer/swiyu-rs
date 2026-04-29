#!/usr/bin/env bash
# Build the didtool Docker image.
# Local tags: didtool:swiyu-beta and didtool:<version>-swiyu-beta
# With --push, also tags as <REGISTRY>/didtool:... and pushes both.
#   REGISTRY defaults to ghcr.io/gubaer; override via env var if needed.
# Other arguments are forwarded to `docker build` (e.g. --no-cache).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="$(grep -m1 '^version' "${SCRIPT_DIR}/Cargo.toml" \
    | sed -E 's/^version *= *"([^"]+)".*/\1/')"

REGISTRY="${REGISTRY:-ghcr.io/gubaer}"

PUSH=0
DOCKER_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --push) PUSH=1 ;;
        *) DOCKER_ARGS+=("$arg") ;;
    esac
done

TAGS=(
    -t "didtool:swiyu-beta"
    -t "didtool:${VERSION}-swiyu-beta"
)

if [[ "${PUSH}" -eq 1 ]]; then
    TAGS+=(
        -t "${REGISTRY}/didtool:swiyu-beta"
        -t "${REGISTRY}/didtool:${VERSION}-swiyu-beta"
    )
fi

cd "${REPO_ROOT}"
docker build \
    -f swiyu-didtool/Dockerfile \
    "${TAGS[@]}" \
    "${DOCKER_ARGS[@]+"${DOCKER_ARGS[@]}"}" \
    .

if [[ "${PUSH}" -eq 1 ]]; then
    docker push "${REGISTRY}/didtool:swiyu-beta"
    docker push "${REGISTRY}/didtool:${VERSION}-swiyu-beta"
fi
