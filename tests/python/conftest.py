"""Load the Lambda handlers under distinct module names (both files are handler.py)."""

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load(alias: str, relative: str) -> None:
    spec = importlib.util.spec_from_file_location(alias, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)


_load("handler_crl", "lambda/crl_freshness_checker/handler.py")
_load("handler_distributor", "lambda/acm_renewal_distributor/handler.py")
sys.path.insert(0, str(ROOT / "scripts"))
