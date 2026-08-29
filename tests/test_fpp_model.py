"""Regression tests for the lightweight FPP model builder."""

import subprocess

from fpp_model import definition_sources


def test_definition_sources_ignore_metadata_above_checkout(tmp_path):
    """Git ignores drive generated-file filtering within the checkout."""
    (tmp_path / "CMakeCache.txt").write_text("ancestor cache")
    root = tmp_path / "test" / "fprime"
    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".gitignore").write_text("build/\n.venv/\n")

    source = root / "Fw" / "Time" / "Time.fpp"
    source.parent.mkdir(parents=True)
    source.write_text("port Time()")

    ignored = root / "build" / "Ignored.fpp"
    ignored.parent.mkdir()
    ignored.write_text("port Ignored()")

    template = root / ".venv" / "template.fpp"
    template.parent.mkdir()
    template.write_text("{% not FPP %}")

    generated = root / "arbitrary-build-name" / "Generated.fpp"
    generated.parent.mkdir()
    (generated.parent / "CMakeCache.txt").write_text("build cache")
    generated.write_text("port Generated()")

    assert definition_sources(root) == [source]
