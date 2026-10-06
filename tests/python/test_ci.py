"""Tests for the CI helper that selects affected workspaces."""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

import affected_workspaces as aw  # noqa: E402

WORKSPACES = json.loads((ROOT / ".github" / "workspaces.json").read_text())


def names(result):
    return sorted(w["workspace"] for w in result)


def test_env_directory_change_only_affects_that_workspace():
    result = aw.affected(WORKSPACES, ["environments/prod/pki-core/main.tf"], None, False)
    assert names(result) == ["pki-core-prod"]


def test_module_change_affects_all_workspaces_of_env():
    result = aw.affected(WORKSPACES, ["modules/pca-subordinate-ca/main.tf"], "nonprod", False)
    assert names(result) == ["pki-core-nonprod", "pki-observability-nonprod", "workload-payments-nonprod"]


def test_docs_change_affects_nothing():
    assert aw.affected(WORKSPACES, ["README.md", "docs/runbooks/crl-expired.md"], None, False) == []


def test_prefix_is_not_confused_with_sibling_directory():
    result = aw.affected(WORKSPACES, ["environments/nonprod/pki-core-old/x.tf"], None, False)
    assert result == []
