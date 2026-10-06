#!/usr/bin/env python3
"""Compute which HCP Terraform workspaces are affected by a set of changed files.

Rules
  - a change under a workspace directory affects that workspace;
  - a change under modules/ or lambda/ affects every workspace (shared code);
  - --all forces every workspace (manual dispatch).

Prints a JSON array of workspace objects, usable as a GitHub Actions matrix:
  python scripts/ci/affected_workspaces.py --env nonprod --changed-files "$(git diff --name-only A B)"
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

SHARED_PREFIXES = ("modules/", "lambda/")


def affected(workspaces: list[dict], changed: list[str], env: str | None, force_all: bool) -> list[dict]:
    changed = [c.strip() for c in changed if c.strip()]
    shared = any(c.startswith(SHARED_PREFIXES) for c in changed)
    result = []
    for ws in workspaces:
        if env and ws["environment"] != env:
            continue
        prefix = ws["directory"].rstrip("/") + "/"
        if force_all or shared or any(c.startswith(prefix) for c in changed):
            result.append(ws)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=".github/workspaces.json")
    parser.add_argument("--changed-files", default="", help="newline or space separated list")
    parser.add_argument("--env", default=None)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    workspaces = json.loads(pathlib.Path(args.config).read_text())
    changed = args.changed_files.split()
    print(json.dumps(affected(workspaces, changed, args.env, args.all)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
