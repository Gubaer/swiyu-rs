# Plan: Explorer-Friendly Docker Images

Companion to [topic-docker-images.md](topic-docker-images.md). Scope: bring `swiyu-issuer` to the *explorer* persona, who runs the stack without cloning the repo and without a Rust toolchain.

## Goals

- An explorer downloads two files (a compose file, a `.env.example`), reads a short README, and runs `docker compose up -d` to get `swiyu-issuer-mgmtapi`, `swiyu-issuer-oidcapi`, Postgres, and Vault running locally.
- All container images are pulled from GitHub Container Registry (GHCR); no local build, no workspace context.
- Existing developer workflow (`docker compose up -d` from `swiyu-issuer/`, which builds locally) keeps working unchanged.

## Non-goals

- Production deployment topology (reverse proxy, sealed Vault, real OAuth2 auth).
- Hosting tutorials or screencasts.
- Cross-architecture coverage beyond `linux/amd64` and `linux/arm64`.
- Wiring `did:webvh` 1.0 into anything explorer-facing — only `did:tdw` 0.3 is testable end-to-end against the SWIYU integration registry.

## Deliverables

1. **Published images on GHCR**, one per runtime binary, built for `linux/amd64` by default with `linux/arm64` as an opt-in via `PLATFORMS`, each tagged `:swiyu-beta` (floating) and `:<version>-swiyu-beta` (pinned) — same convention as `swiyu-didtool` already uses on `master`:
   - `ghcr.io/<owner>/swiyu-issuer-mgmtapi`
   - `ghcr.io/<owner>/swiyu-issuer-oidcapi`
   - `ghcr.io/<owner>/swiyu-issuer-cli`
2. **Standalone compose file** `swiyu-issuer/deploy/explorer/docker-compose.yml` that pulls those images (no `build:` keys).
3. **Standalone env template** `swiyu-issuer/deploy/explorer/.env.example` tuned for the explorer flow.
4. **README** `swiyu-issuer/deploy/explorer/README.md` with the onboarding walk-through.
5. **Bash script** `swiyu-issuer/deploy/explorer/publish-images.sh` that builds and pushes the three images to GHCR from a developer's machine. A GitHub Actions workflow for the same job is **deferred** to a later iteration.

## File layout

```
swiyu-issuer/
├── deploy/
│   └── explorer/
│       ├── docker-compose.yml      # pulls from ghcr.io, no build context
│       ├── .env.example            # subset of swiyu-issuer/.env.example, retuned
│       ├── publish-images.sh       # build + push to GHCR (manual, dev machine)
│       └── README.md               # walk-through (see below)
└── …
```

The developer-facing `swiyu-issuer/docker-compose.yml` and `swiyu-issuer/Dockerfile` are unchanged. No `.github/workflows/` changes in this iteration.

## Image publishing — `swiyu-issuer/deploy/explorer/publish-images.sh`

A `bash` script run manually from a developer's machine, **modelled directly on the existing `swiyu-didtool/build-image.sh` on `master`**. That script encodes three decisions we want to inherit verbatim:

1. **`-swiyu-beta` is hard-coded into every published tag** — both a floating `<image>:swiyu-beta` and a pinned `<image>:<version>-swiyu-beta`. The beta marker is a literal string in `TAGS=(...)`, not derived from version state, so there is no code path that produces a non-beta tag. This is deliberate: the issuer software is beta *and*, more importantly, the wider SWIYU ecosystem is beta — the tag must communicate that unconditionally. The explorer images inherit the same rule; concrete examples are listed under the tag scheme below (`swiyu-issuer-mgmtapi:swiyu-beta`, `swiyu-issuer-mgmtapi:0.1.12-swiyu-beta`, and so on — the word `didtool` never appears in an issuer tag).
2. **`VERSION` is read from `Cargo.toml`** — the script greps the first `version = "…"` line of `swiyu-didtool/Cargo.toml`. No `git describe`, no commit-SHA suffix, no clean/dirty distinction. The crate version is the source of truth.
3. **`REGISTRY` defaults to `ghcr.io/gubaer`** with an env-var override; `--push` is a flag, not an env var; all other positional args are forwarded to `docker build` (e.g. `--no-cache`). Local-only by default, push opt-in.

The explorer script extends the same shape to three images instead of one. CI/CD for the same job is **deferred** — once the script is stable and the explorer flow is validated end-to-end, we can lift it into a `.github/workflows/publish-images.yml` (matrix over the three targets, `docker/build-push-action`, GHCR via `GITHUB_TOKEN`).

Script shape:

- `#!/usr/bin/env bash` with `set -euo pipefail`.
- **Inputs** (mirroring `swiyu-didtool/build-image.sh`):
  - `REGISTRY` — env var, defaults to `ghcr.io/gubaer` (same default the didtool script uses today). Override for a fork.
  - `VERSION` — derived inside the script by grepping the first `version = "…"` line out of `swiyu-issuer/Cargo.toml` (currently `0.1.12`). Not an env input.
  - `--push` flag — when present, also tag with the `${REGISTRY}/` prefix and `docker push`. Without it, the script only applies local tags.
  - `PLATFORMS` — env var, defaults to `linux/amd64`. Multi-arch (`linux/amd64,linux/arm64`) is opt-in until we've measured how long the `arm64` cargo-chef cook actually takes on a contributor's laptop. (Note: master's `build-image.sh` is single-arch and uses plain `docker build`; this script uses `docker buildx build` because multi-arch is on the table here.)
  - All other positional args are forwarded to `docker buildx build`, exactly like the didtool script forwards them to `docker build`.
- **Tag scheme — inherited unchanged from master**:
  - Local tags applied to every build, per image (`swiyu-issuer-mgmtapi`, `swiyu-issuer-oidcapi`, `swiyu-issuer-cli`):
    - `swiyu-issuer-<name>:swiyu-beta` (floating)
    - `swiyu-issuer-<name>:<VERSION>-swiyu-beta` (pinned, e.g. `swiyu-issuer-mgmtapi:0.1.12-swiyu-beta`)
  - With `--push`, the same two tags are additionally applied with the `${REGISTRY}/` prefix and `docker push`ed.
  - There is **no `:latest`**, no `git describe`-derived suffix, no `ALLOW_DIRTY` guard, no clean/dirty distinction. The `-swiyu-beta` literal is appended unconditionally — same guarantee `swiyu-didtool/build-image.sh` already enforces. Closes the "latest-tag policy" question that earlier drafts of this plan listed as open.
- **Preflight checks**:
  - `docker buildx version` succeeds.
  - `docker buildx inspect` shows a builder that supports `PLATFORMS` (script prints the `docker buildx create --use` hint if it doesn't).
  - With `--push`, `docker login ghcr.io` must have a valid credential. The script does NOT call `docker login` itself — the user logs in once with their PAT before running. (Master's didtool script trusts the user to be logged in the same way.)
  - Working directory is the workspace root (the Dockerfile's `path = "../..."` workspace deps require it). The script `cd`s there itself based on its own location — same pattern as `swiyu-didtool/build-image.sh` (`REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"`).
- **Build + push loop** over the three runtime stages (`runtime-mgmtapi`, `runtime-oidcapi`, `runtime-cli`):
  - `docker buildx build` with `--target <stage>`, `--platform "$PLATFORMS"`, one `--tag` per entry in the tag scheme above, and `--push` when the `--push` flag is set (else `--load`).
  - Buildx cache: `--cache-from type=registry,ref=${REGISTRY}/swiyu-issuer-<name>:buildcache` and `--cache-to …,mode=max`. Keeps successive runs incremental even when the local `cargo-chef` planner layer is gone. (This is the one thing the explorer script genuinely adds over master's: didtool is small enough that registry cache wasn't needed; the issuer build is heavier.)
- **Output**: on success, prints one line per pushed image with its full `${REGISTRY}/…@sha256:…` digest. The explorer compose file can then pin to a digest if it wants byte-level reproducibility.

Platform coverage of the published image — decided:

- An `linux/amd64` image runs natively on amd64 Linux, Windows (WSL2), and Intel Macs. It also *runs* on Apple Silicon Macs, arm64 Linux (Raspberry Pi, AWS Graviton), and Windows on ARM — but only through QEMU / Rosetta emulation. Emulation usually works for Rust binaries but is noticeably slower at startup and occasionally hits emulation bugs around atomic ops or newer instructions.
- A multi-arch image (`linux/amd64,linux/arm64`) covers Apple Silicon and arm64 Linux natively. The cost is on the build side: cross-compiling the cargo-chef cook step for `arm64` on an amd64 builder goes through QEMU and is much slower than a native amd64 build.

The script defaults to `linux/amd64` so the first release ships fast. `linux/arm64` can be added later by setting `PLATFORMS=linux/amd64,linux/arm64`. The explorer README acknowledges the emulation behaviour up front so an Apple Silicon user is not surprised by slower container startup.

## Standalone compose file — `swiyu-issuer/deploy/explorer/docker-compose.yml`

Differences from `swiyu-issuer/docker-compose.yml`:

- Each app service uses `image: ghcr.io/<owner>/swiyu-issuer-<name>:${IMAGE_TAG:-swiyu-beta}` and **drops the `build:` key entirely**. The default falls back to the floating `swiyu-beta` tag, matching the master didtool convention.
- `bootstrap-dev-tenant` likewise pulls `ghcr.io/<owner>/swiyu-issuer-cli:${IMAGE_TAG:-swiyu-beta}`; the inline shell that runs the two-phase CLI seed is identical.
- Same Postgres + Vault + vault-init services, same healthchecks, same env-var fallbacks.
- Header comment is rewritten for the explorer audience: "no clone, no cargo, no build — just `docker compose up -d`."
- `name:` stays `swiyu-issuer` so a developer who later clones the repo doesn't end up with two parallel project namespaces.

That's a near copy of the developer compose with `build:` removed. Worth keeping two files (rather than overlay/profiles) because:

- The developer file is read top-to-bottom by contributors — adding `image:` lines they'll never use is noise.
- An overlay model means the explorer must download two compose files and remember the `-f a.yml -f b.yml` invocation; the whole point is "one file, one command."

## Standalone env template — `swiyu-issuer/deploy/explorer/.env.example`

Trimmed copy of `swiyu-issuer/.env.example`. Sections to keep:

- `DATABASE_URL` + `POSTGRES_*` (defaults work as-is).
- `VAULT_DEV_ROOT_TOKEN_ID`, `SIGNING_ENGINE`, `SECRET_ENCRYPTION_ENGINE`, `SECRET_ENCRYPTION_DEV_MASTER_KEY`, `VAULT_ADDR`, `VAULT_TOKEN`.
- `SWIYU_IDENTIFIER_REGISTRY_URL`, `SWIYU_STATUS_REGISTRY_URL`, `SWIYU_TOKEN_URL` (defaults point at INT — fine for explorers).
- `DEV_TENANT_PARTNER_ID`, `DEV_TENANT_DISPLAY_NAME`, `DEV_TENANT_DESCRIPTION`, `DEV_TENANT_CLIENT_ID`, `DEV_TENANT_CLIENT_SECRET`, `DEV_TENANT_REFRESH_TOKEN` (the explorer's onboarding fills these in).
- `ISSUER_BASE_URL`, `ISSUER_MGMT_HOST_PORT`, `ISSUER_OIDC_HTTP_URL`, `RUST_LOG`.
- New: `IMAGE_TAG` (default `swiyu-beta`) — pinning to `<version>-swiyu-beta` (e.g. `0.1.12-swiyu-beta`) lets an explorer follow a specific release rather than the floating beta tag. The `:swiyu-beta` / `:<version>-swiyu-beta` convention is inherited from `swiyu-didtool/build-image.sh` on master; the issuer images use their own names (`swiyu-issuer-mgmtapi` etc.) — `didtool` is never part of an issuer tag.

Sections to drop:

- `BIND_ADDR`, `BIND_ADDR_OIDC` — overridden inside the container; an explorer never edits them.
- `ACCESS_TOKEN_TTL_SECONDS`, `C_NONCE_TTL_SECONDS` — defaults are fine, commented note is enough.
- Comments referring to `cargo run` — replace each with the equivalent `docker compose run --rm` invocation.
- Anything mentioning examples/smoke binaries (those require a workspace checkout).

Header comment makes clear: this file is for explorers; contributors use `swiyu-issuer/.env.example` instead.

## Explorer README — `swiyu-issuer/deploy/explorer/README.md`

Five short sections:

1. **Prerequisites** — Docker Engine 25+ with Compose v2, a SWIYU ePortal account for the business-entity onboarding.
2. **Download** — two `curl -O` commands pointing at the raw files on `master`; a sentence noting `IMAGE_TAG=<version>-swiyu-beta` (e.g. `0.1.12-swiyu-beta`) for pinning to a specific release, versus the default floating `swiyu-beta`. The README calls out explicitly that "beta" is intentional and reflects both the issuer software and the SWIYU ecosystem.
3. **Onboard a sample business entity** — step-by-step against the SWIYU ePortal: register a business partner, generate customer key/secret, generate a renewal token. Lifted from the documented flow in `swiyu-issuer/.env.example` lines 169–232, paraphrased for someone seeing this for the first time. Outcome: four values the explorer has on hand.
4. **Fill in `.env`** — `cp .env.example .env`, then paste the four ePortal values into `DEV_TENANT_PARTNER_ID`, `DEV_TENANT_CLIENT_ID`, `DEV_TENANT_CLIENT_SECRET`, `DEV_TENANT_REFRESH_TOKEN`. One sentence on what each is and how long it lives (refresh token has a 7-day cliff — covered already in `.env.example`).
5. **Run** — `docker compose up -d`, then `docker compose logs -f bootstrap-dev-tenant` to see the tenant id, then `docker compose run --rm swiyu-issuer-cli tenant api-token mint --tenant <id> --name explorer` to get a bearer token. Curl a couple of endpoints (`/healthz`, then a credential-offer round-trip) to confirm it works.

A short **Troubleshooting** appendix at the end: refresh-token rotation (`docker compose run --rm swiyu-issuer-cli tenant import-oauth-refresh-token --tenant <id> --token-stdin`), wiping state (`docker compose down -v`), and where logs live.

## Validation steps before announcing

Each step is something the user can run; the assistant does not execute `cargo`/`docker` for them.

- [ ] `cargo fmt --check && cargo clippy -- -D warnings` from the workspace root — proves the plan introduced no Rust changes that need formatting.
- [ ] `shellcheck swiyu-issuer/deploy/explorer/publish-images.sh` clean.
- [ ] Dry run: `swiyu-issuer/deploy/explorer/publish-images.sh` (no `--push`) builds all three images locally and applies the `:swiyu-beta` + `:<version>-swiyu-beta` local tags only.
- [ ] Real push: `swiyu-issuer/deploy/explorer/publish-images.sh --push` to a test namespace (`REGISTRY=ghcr.io/<test-namespace>`); confirm the three packages appear on GHCR with the `swiyu-beta` and `<version>-swiyu-beta` tags and that no `:latest` was created.
- [ ] On a clean machine with only Docker installed: `curl -O` the two files, fill in `.env`, `docker compose up -d`, mint an API token, hit `/healthz` on both ports.
- [ ] If multi-arch is enabled, repeat the explorer flow on `linux/arm64` (Apple Silicon Mac).
- [ ] Bring the developer-facing stack up from `swiyu-issuer/` and confirm nothing changed (`docker compose up -d --build` still works, images still tagged locally).

## Decided

- **Repository owner / image namespace: `Gubaer`.** `REGISTRY` defaults to `ghcr.io/gubaer` (GHCR paths are lowercase; the GitHub owner slug is `Gubaer`). Matches `swiyu-didtool/build-image.sh` on master, so both scripts publish under the same namespace.
- **Package visibility: public.** The three GHCR packages (`swiyu-issuer-mgmtapi`, `swiyu-issuer-credential-issuance`, `swiyu-issuer-cli`) are published as public, so the explorer's `docker compose pull` works without a `docker login` step and the README does not need to document PAT setup.
