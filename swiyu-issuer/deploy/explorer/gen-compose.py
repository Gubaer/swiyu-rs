#!/usr/bin/env python3
"""Generate the explorer docker-compose.yml from the dev docker-compose.yml.

From swiyu-issuer/deploy/explorer/:

  uv run gen-compose.py            # write
  uv run gen-compose.py --check    # CI guard

The dev compose at swiyu-issuer/docker-compose.yml is the single source of
truth; the explorer copy is regenerated whenever the dev compose changes.
Dependencies (ruamel.yaml) are pinned via this directory's pyproject.toml
and uv.lock — `uv run` provisions the venv on first use.
"""

import argparse
import difflib
import io
import sys
from pathlib import Path

try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write(
        "error: ruamel.yaml is required. From swiyu-issuer/deploy/explorer/:\n"
        "  uv sync && uv run gen-compose.py\n"
    )
    sys.exit(2)

REGISTRY = "ghcr.io/gubaer"

# Dev-compose service name -> image name in the registry. bootstrap-dev-tenant
# uses the same image as swiyu-issuer-cli (different entrypoint, two-phase seed).
SERVICE_TO_IMAGE = {
    "swiyu-issuer-mgmtapi": "swiyu-issuer-mgmtapi",
    "swiyu-issuer-oidcapi": "swiyu-issuer-oidcapi",
    "swiyu-issuer-cli": "swiyu-issuer-cli",
    "bootstrap-dev-tenant": "swiyu-issuer-cli",
}

EXPLORER_HEADER = """\
# swiyu-issuer explorer stack — pulls published images from GHCR.
#
# Goal: no clone, no cargo, no build — just `docker compose up -d`.
#
# GENERATED FILE. Do not edit by hand. The source of truth is
# swiyu-issuer/docker-compose.yml; regenerate with
#   python3 swiyu-issuer/deploy/explorer/gen-compose.py
# CI runs `gen-compose.py --check` to block drift.
#
# IMAGE_TAG defaults to the floating `swiyu-beta`. Pin to a release by
# setting e.g. IMAGE_TAG=0.1.12-swiyu-beta in .env.
"""


def transform(data) -> None:
    services = data["services"]
    for service_name, image_name in SERVICE_TO_IMAGE.items():
        if service_name not in services:
            sys.stderr.write(
                f"error: dev compose missing expected service '{service_name}'\n"
            )
            sys.exit(2)
        service = services[service_name]
        if "build" in service:
            del service["build"]
        # `profiles` makes sense in the dev compose (keeps the CLI service
        # out of `docker compose up`), but the explorer compose has no
        # always-on CLI to hide, so drop it if present.
        if "profiles" in service:
            del service["profiles"]
        service["image"] = (
            f"{REGISTRY}/{image_name}:" + "${IMAGE_TAG:-swiyu-beta}"
        )
        service.move_to_end("image", last=False)

    # Replace the dev-compose top header with the explorer-audience version.
    # yaml_set_start_comment attaches to the document root; clearing the
    # existing comment list first ensures the dev header is not preserved
    # alongside the new one.
    if data.ca.comment is not None:
        data.ca.comment[1] = []
    data.yaml_set_start_comment(EXPLORER_HEADER)


def generate(dev_compose: Path) -> str:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 4096  # don't reflow long scalar values

    with dev_compose.open("r", encoding="utf-8") as f:
        data = yaml.load(f)

    transform(data)

    buf = io.StringIO()
    yaml.dump(data, buf)
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed explorer compose is stale",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    dev_compose = script_dir.parent.parent / "docker-compose.yml"
    out_path = script_dir / "docker-compose.yml"

    generated = generate(dev_compose)

    if args.check:
        existing = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
        if generated != existing:
            sys.stderr.write(
                f"error: {out_path} is stale — regenerate with gen-compose.py\n"
            )
            sys.stdout.writelines(
                difflib.unified_diff(
                    existing.splitlines(keepends=True),
                    generated.splitlines(keepends=True),
                    fromfile=str(out_path),
                    tofile="<generated>",
                )
            )
            return 1
        return 0

    out_path.write_text(generated, encoding="utf-8")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
