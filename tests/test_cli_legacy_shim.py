from pathlib import Path
import runpy

from cryptologik_cli.main import cli


def test_legacy_cli_shim_imports_without_side_effects():
    namespace = runpy.run_path(
        str(Path(__file__).resolve().parent.parent / "cli" / "main.py")
    )

    assert namespace["cli"] is cli
