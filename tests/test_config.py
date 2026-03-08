"""Tests for the config parser (src/config.py)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest  # type: ignore[import-untyped]

from src.config import ManifestEntry, TriageEntry, parse_config, parse_manifest, parse_triage


class TestParseConfig:
    """Test the full parse_config function."""

    def test_parses_both_tables(self, config_md: Path) -> None:
        result = parse_config(config_md)
        assert "manifest" in result
        assert "triage" in result
        assert len(result["manifest"]) == 2
        assert len(result["triage"]) == 2

    def test_manifest_entries_have_correct_fields(self, config_md: Path) -> None:
        manifest = parse_manifest(config_md)
        entry = manifest[0]
        assert isinstance(entry, ManifestEntry)
        assert entry.component_name == "Frontend"
        assert "frontend" in entry.path
        assert entry.description == "React dashboard"

    def test_triage_entries_have_correct_fields(self, config_md: Path) -> None:
        triage = parse_triage(config_md)
        assert "CVE-2021-44228" in triage
        entry = triage["CVE-2021-44228"]
        assert isinstance(entry, TriageEntry)
        assert entry.status == "known_not_affected"
        assert entry.justification == "vulnerable_code_not_in_execute_path"

    def test_triage_affected_has_no_justification(self, config_md: Path) -> None:
        triage = parse_triage(config_md)
        entry = triage["CVE-2023-44487"]
        assert entry.status == "known_affected"
        assert entry.justification == ""

    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            parse_config(tmp_path / "nonexistent.md")

    def test_missing_manifest_section_raises(self, tmp_path: Path) -> None:
        bad_md = tmp_path / "bad.md"
        bad_md.write_text("# No tables here\n\nJust text.\n")
        with pytest.raises(ValueError, match="SBOM Manifest"):
            parse_config(bad_md)

    def test_triage_section_optional(self, tmp_path: Path) -> None:
        """A config with only the manifest table is valid (triage is empty)."""
        md = textwrap.dedent("""\
            ## SBOM Manifest

            | Component Name | Path         | Description |
            |----------------|--------------|-------------|
            | App            | app.spdx.json| The app     |
        """)
        p = tmp_path / "manifest-only.md"
        p.write_text(md)
        result = parse_config(p)
        assert len(result["manifest"]) == 1
        assert result["triage"] == {}
