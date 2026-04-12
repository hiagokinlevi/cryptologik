from pathlib import Path

import pytest
from click import ClickException

from cryptologik_cli.main import _write_utf8_text


def test_write_utf8_text_rejects_symlinked_output_file(tmp_path: Path):
    real_output = tmp_path / "report.json"
    real_output.write_text("", encoding="utf-8")
    symlink_path = tmp_path / "report-link.json"
    symlink_path.symlink_to(real_output)

    with pytest.raises(ClickException, match="symlinked files are not allowed"):
        _write_utf8_text(str(symlink_path), "{}", "report output")


def test_write_utf8_text_rejects_symlinked_parent_directory(tmp_path: Path):
    real_dir = tmp_path / "real-output"
    real_dir.mkdir()
    symlink_dir = tmp_path / "linked-output"
    symlink_dir.symlink_to(real_dir, target_is_directory=True)

    with pytest.raises(ClickException, match="symlinked directories are not allowed"):
        _write_utf8_text(str(symlink_dir / "report.json"), "{}", "report output")
