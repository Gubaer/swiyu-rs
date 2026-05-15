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
2. **Standalone compose file** `swiyu-issuer/deploy/explorer/docker-compose.yml` that pulls those images (no `build:` keys). **Generated** from `swiyu-issuer/docker-compose.yml` by deliverable 6 and committed; the dev compose is the single source of truth.
3. **Standalone env template** `swiyu-issuer/deploy/explorer/.env.example` tuned for the explorer flow.
4. **README** `swiyu-issuer/deploy/explorer/README.md` with the onboarding walk-through.
5. **Bash script** `swiyu-issuer/deploy/explorer/publish-images.sh` that builds and pushes the three images to GHCR from a developer's machine. A GitHub Actions workflow for the same job is **deferred** to a later iteration.
6. **Compose generator** `swiyu-issuer/deploy/explorer/gen-compose.py` — Python (using `ruamel.yaml` for comment-preserving round-trip) that produces `docker-compose.yml` from `swiyu-issuer/docker-compose.yml` by applying the transformation rules in the "Standalone compose file" section. Supports a `--check` mode that diffs the committed output against what the generator would emit and exits non-zero if stale, so drift is catchable in CI.

## File layout

```
swiyu-issuer/
├── deploy/
│   └── explorer/
│       ├── docker-compose.yml      # GENERATED from swiyu-issuer/docker-compose.yml, committed
│       ├── gen-compose.py          # regenerator (Python + ruamel.yaml); source of truth for the file above
│       ├── .env.example            # subset of swiyu-issuer/.env.example, retuned
│       ├── publish-images.sh       # build + push to GHCR (manual, dev machine)
│       └── README.md               # walk-through (see below)
└── …
```

The developer-facing `swiyu-issuer/docker-compose.yml` is unchanged. `swiyu-issuer/Dockerfile` gets `LABEL org.opencontainers.image.*` blocks added per runtime stage (see "Image labels" below) — additive, no runtime effect, no impact on the developer flow. No `.github/workflows/` changes in this iteration.

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

## Image labels

Every published image carries OCI image metadata (`org.opencontainers.image.*`). The load-bearing label is `source`: GHCR uses it to auto-link the published package to this repo (README rendering on the package page, inherited visibility, "Repository" link in the package settings). Without it the package looks orphaned. The remaining labels make `docker inspect` and scanner output (Trivy, Grype, Renovate, the GHCR UI) meaningful. Same pattern `swiyu-didtool/Dockerfile` already uses on `master`, extended to three stages and rounded out with a few more fields.

**Static labels** — set as `LABEL` directives in `swiyu-issuer/Dockerfile`, one block per runtime stage:

| Label | Value |
|---|---|
| `org.opencontainers.image.title` | `swiyu-issuer-mgmtapi`, `swiyu-issuer-oidcapi`, `swiyu-issuer-cli` (per stage) |
| `org.opencontainers.image.description` | one-line per stage (e.g. "SWIYU issuer — management API") |
| `org.opencontainers.image.source` | `https://github.com/Gubaer/swiyu-rs` |
| `org.opencontainers.image.url` | `https://github.com/Gubaer/swiyu-rs` |
| `org.opencontainers.image.documentation` | `https://github.com/Gubaer/swiyu-rs/tree/master/swiyu-issuer` |
| `org.opencontainers.image.vendor` | `Gubaer` |
| `org.opencontainers.image.licenses` | SPDX expression matching `LICENSE` (currently `MIT`) |

`LABEL` directives have no runtime effect and do not change the image's executable contents — this is the only change the plan makes to `swiyu-issuer/Dockerfile`, and the developer flow (`docker compose up -d --build` from `swiyu-issuer/`) is unaffected.

**Dynamic labels** — passed via `--label` from `publish-images.sh` so they describe the build, not the source tree:

| Label | Source |
|---|---|
| `org.opencontainers.image.version` | `${VERSION}` (already grepped from `swiyu-issuer/Cargo.toml`) |
| `org.opencontainers.image.revision` | `git rev-parse HEAD` |
| `org.opencontainers.image.created` | `date -u +%Y-%m-%dT%H:%M:%SZ` (RFC 3339, UTC) |

New script preconditions: `git` and `date` available on `PATH`. The `date -u +%Y-%m-%dT%H:%M:%SZ` format string works on GNU coreutils (Linux/WSL) and BSD `date` (macOS) identically. If `git rev-parse HEAD` fails (script run outside a checkout), the script aborts before any build so no label-less image is ever published.

`buildx` propagates `--label` to every platform manifest, so multi-arch builds keep their metadata intact. A dev who runs `docker compose up -d --build` from `swiyu-issuer/` gets the static labels (from the Dockerfile) but no version/revision/created — expected, since the dev image is not being published.

## Standalone compose file — `swiyu-issuer/deploy/explorer/docker-compose.yml`

The explorer compose is **generated** from `swiyu-issuer/docker-compose.yml` by `swiyu-issuer/deploy/explorer/gen-compose.py` and committed. The dev compose is the single source of truth; the explorer copy is regenerated whenever the dev compose changes. `gen-compose.py --check` re-runs the transform and exits non-zero (with a diff on stdout) when the committed output is stale, so drift is impossible to merge without noticing.

Transformation rules the generator applies:

- For each app service (`swiyu-issuer-mgmtapi`, `swiyu-issuer-oidcapi`, `swiyu-issuer-cli`): delete the `build:` block, insert `image: ghcr.io/gubaer/swiyu-issuer-<name>:${IMAGE_TAG:-swiyu-beta}`.
- `bootstrap-dev-tenant`: same swap, against `swiyu-issuer-cli`. The inline shell that runs the two-phase CLI seed is passed through unchanged.
- Replace the top header comment with the explorer-audience version ("no clone, no cargo, no build — just `docker compose up -d`.").
- Everything else passes through verbatim: Postgres + Vault + vault-init services, healthchecks, env-var fallbacks, `name: swiyu-issuer` (so a developer who later clones the repo doesn't end up with two parallel project namespaces).

Tooling choice: **Python + `ruamel.yaml`**. `ruamel.yaml` round-trips YAML while preserving comments, key order, and quoting style — important because the generated file is committed and reviewers read it as a normal compose file, not a generator artefact. PyYAML would lose comments; `yq` (Mike Farah's Go version) preserves most formatting but mangles multi-line shell heredocs in `bootstrap-dev-tenant`. The generator is small (~30–50 lines).

Why generate rather than maintain two copies or use Compose overlays:

- **Drift-proof**: the dev compose is the only file humans edit. `gen-compose.py --check` is the pre-commit / CI guardrail.
- **One file, one curl for explorers**: the generated compose is a standalone file with no `-f overlay.yml` required.
- **Reviewable**: the generated file is committed, so reviewers see the YAML diff in PRs, not the generator output as a black box.

When the dev compose changes, the workflow is: edit `swiyu-issuer/docker-compose.yml`, run `gen-compose.py`, commit both files in the same PR. CI runs `gen-compose.py --check` and blocks the merge if they're out of sync.

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

## Implementation steps

Linear sequence. Each step lands one artifact or one operational change; the next step does not begin until the previous one is in shape to merge. Preconditions already satisfied on `master`: `swiyu-issuer/Dockerfile` exposes the three runtime stages (`runtime-mgmtapi`, `runtime-oidcapi`, `runtime-cli`) the publish script targets, and `swiyu-didtool/build-image.sh` is the reference implementation for the script's shape.

1. **Scaffold the deploy directory.** Create `swiyu-issuer/deploy/explorer/`. No files yet — this keeps the path stable so subsequent commits can each land one artifact.

2. **Author `publish-images.sh`.** Start from a literal copy of `swiyu-didtool/build-image.sh` and apply the extensions documented under "Image publishing" above: switch `docker build` → `docker buildx build`; loop over the three `--target` stages (`runtime-mgmtapi`, `runtime-oidcapi`, `runtime-cli`); read `VERSION` from `swiyu-issuer/Cargo.toml`; apply per-image tags `swiyu-issuer-<name>:swiyu-beta` and `swiyu-issuer-<name>:${VERSION}-swiyu-beta`; honour `PLATFORMS` (default `linux/amd64`) and `REGISTRY` (default `ghcr.io/gubaer`); preserve the `--push` flag and the `REPO_ROOT` cd-from-script-location pattern; add `--cache-from`/`--cache-to type=registry,ref=${REGISTRY}/swiyu-issuer-<name>:buildcache,mode=max`. Mark executable (`chmod +x`). Confirm `shellcheck` is clean and a no-push dry run produces all three images locally before committing.

3. **Add OCI image labels.** Add a `LABEL org.opencontainers.image.*` block to each of the three runtime stages in `swiyu-issuer/Dockerfile` per the "Image labels" section above (static labels). Extend `publish-images.sh` to pass the three dynamic labels (`version`, `revision`, `created`) via `--label` on every `docker buildx build` invocation, sourcing values from `${VERSION}`, `git rev-parse HEAD`, and `date -u +%Y-%m-%dT%H:%M:%SZ` respectively; fail fast (`set -euo pipefail` already covers this) if `git` cannot resolve `HEAD`. After a no-push dry run, verify with `docker buildx imagetools inspect <local-tag>` (or `docker inspect <local-tag> --format '{{json .Config.Labels}}'`) that all expected labels are populated on each of the three images.

4. **Author `gen-compose.py` and run it to produce `docker-compose.yml`.** Write `swiyu-issuer/deploy/explorer/gen-compose.py` (Python + `ruamel.yaml`) implementing the transformation rules in the "Standalone compose file" section: drop `build:` on each app service, insert `image: ghcr.io/gubaer/swiyu-issuer-<name>:${IMAGE_TAG:-swiyu-beta}`, do the same for `bootstrap-dev-tenant`, swap the header comment. Add a `--check` mode that re-runs the transform against the dev compose and exits non-zero (with a unified diff on stdout) if the committed output is stale — this is the drift guard. Run the generator once to produce `swiyu-issuer/deploy/explorer/docker-compose.yml`; commit both `gen-compose.py` and the produced file. Validate the result with `docker compose -f swiyu-issuer/deploy/explorer/docker-compose.yml config -q`.

5. **Author `.env.example`.** Copy `swiyu-issuer/.env.example` and trim it per the sections-to-keep / sections-to-drop lists above. Rewrite each `cargo run` comment as the equivalent `docker compose run --rm` invocation. Append `IMAGE_TAG=swiyu-beta` with a short note explaining how to pin to `<version>-swiyu-beta`. Header comment marks the file as explorer-targeted and points contributors at `swiyu-issuer/.env.example` instead.

6. **Author `README.md`.** Five sections per the "Explorer README" outline above (prerequisites, download, ePortal onboarding, fill `.env`, run), plus the troubleshooting appendix. Lift the ePortal walkthrough from `swiyu-issuer/.env.example` lines 169–232 and paraphrase for a first-time reader.

7. **First push to GHCR under `Gubaer`.** Log in once with `docker login ghcr.io` using a PAT scoped to `write:packages`; run `./swiyu-issuer/deploy/explorer/publish-images.sh --push`. Verify the three packages appear on GHCR with both `:swiyu-beta` and `:<version>-swiyu-beta` and that no `:latest` was created.

8. **Set GHCR package visibility to public.** For each of `swiyu-issuer-mgmtapi`, `swiyu-issuer-oidcapi`, `swiyu-issuer-cli`, flip the package visibility to public so an explorer's `docker compose pull` works without a `docker login` step. Confirm each package's "Repository" link on GHCR now points back at `gubaer/swiyu-rs` (proves the `source` label took effect).

9. **Run validation.** Walk the checklist under "Validation steps before announcing" below.

10. **Announce.** Once validation is clean, link the explorer README from the top-level `README.md` and announce on the relevant channel.

11. **Deferred follow-ups.** Promote `PLATFORMS=linux/amd64,linux/arm64` to the default after measuring arm64 cook time on a contributor laptop. Lift `publish-images.sh` into `.github/workflows/publish-images.yml` (matrix over the three targets, `docker/build-push-action`, GHCR via `GITHUB_TOKEN`). Optionally pin the explorer compose to image digests for byte-level reproducibility.

## Validation steps before announcing

Each step is something the user can run; the assistant does not execute `cargo`/`docker` for them.

- `cargo fmt --check && cargo clippy -- -D warnings` from the workspace root — proves the plan introduced no Rust changes that need formatting.
- `shellcheck swiyu-issuer/deploy/explorer/publish-images.sh` clean.
- `python3 swiyu-issuer/deploy/explorer/gen-compose.py --check` exits 0 — committed explorer compose is in sync with the dev compose.
- `docker compose -f swiyu-issuer/deploy/explorer/docker-compose.yml config -q` parses without error.
- Dry run: `swiyu-issuer/deploy/explorer/publish-images.sh` (no `--push`) builds all three images locally and applies the `:swiyu-beta` + `:<version>-swiyu-beta` local tags only.
- Real push: `swiyu-issuer/deploy/explorer/publish-images.sh --push` to a test namespace (`REGISTRY=ghcr.io/<test-namespace>`); confirm the three packages appear on GHCR with the `swiyu-beta` and `<version>-swiyu-beta` tags and that no `:latest` was created.
- `docker buildx imagetools inspect ghcr.io/gubaer/swiyu-issuer-<name>:<version>-swiyu-beta` (or `docker inspect …` on a local tag) returns all expected `org.opencontainers.image.*` labels populated — title differs per image, version/revision/created reflect the build, source/url/documentation/vendor/licenses match the static block.
- On GHCR, each of the three packages auto-links to `gubaer/swiyu-rs` (the package page shows the repo README and a "Repository" link) — confirms the `source` label took effect end-to-end.
- On a clean machine with only Docker installed: `curl -O` the two files, fill in `.env`, `docker compose up -d`, mint an API token, hit `/healthz` on both ports.
- If multi-arch is enabled, repeat the explorer flow on `linux/arm64` (Apple Silicon Mac).
- Bring the developer-facing stack up from `swiyu-issuer/` and confirm nothing changed (`docker compose up -d --build` still works, images still tagged locally).

## Decided

- **Repository owner / image namespace: `Gubaer`.** `REGISTRY` defaults to `ghcr.io/gubaer` (GHCR paths are lowercase; the GitHub owner slug is `Gubaer`). Matches `swiyu-didtool/build-image.sh` on master, so both scripts publish under the same namespace.
- **Package visibility: public.** The three GHCR packages (`swiyu-issuer-mgmtapi`, `swiyu-issuer-oidcapi`, `swiyu-issuer-cli`) are published as public, so the explorer's `docker compose pull` works without a `docker login` step and the README does not need to document PAT setup.
