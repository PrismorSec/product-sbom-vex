"""Tests for VEX generation (src/vex.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest  # type: ignore[import-untyped]

from src.config import TriageEntry, parse_triage
from src.vex import generate_vex


class TestGenerateVEX:
    """Verify CSAF 2.0 VEX generation with triage overrides."""

    def test_vex_file_is_written(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        result = generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        assert result.exists()

    def test_csaf_top_level_keys(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        with out.open() as fh:
            doc = json.load(fh)

        assert "document" in doc
        assert "product_tree" in doc
        assert "vulnerabilities" in doc

    def test_csaf_version_is_2_0(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        with out.open() as fh:
            doc = json.load(fh)

        assert doc["document"]["csaf_version"] == "2.0"
        assert doc["document"]["category"] == "csaf_vex"

    def test_product_tree_has_branches(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        with out.open() as fh:
            doc = json.load(fh)

        branches = doc["product_tree"]["branches"]
        assert len(branches) > 0

    def test_triage_override_known_not_affected(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        """CVE-2021-44228 is triaged as known_not_affected."""
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        with out.open() as fh:
            doc = json.load(fh)

        log4j_vuln = None
        for v in doc["vulnerabilities"]:
            if v["cve"] == "CVE-2021-44228":
                log4j_vuln = v
                break

        assert log4j_vuln is not None, "CVE-2021-44228 not found in VEX"
        assert "known_not_affected" in log4j_vuln["product_status"]

    def test_triage_override_known_affected(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        """CVE-2023-44487 is triaged as known_affected."""
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        with out.open() as fh:
            doc = json.load(fh)

        rapid_reset = None
        for v in doc["vulnerabilities"]:
            if v["cve"] == "CVE-2023-44487":
                rapid_reset = v
                break

        assert rapid_reset is not None
        assert "known_affected" in rapid_reset["product_status"]

    def test_untriaged_defaults_to_under_investigation(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        """CVE-2099-99999 is NOT in triage → defaults to under_investigation."""
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        with out.open() as fh:
            doc = json.load(fh)

        future_vuln = None
        for v in doc["vulnerabilities"]:
            if v["cve"] == "CVE-2099-99999":
                future_vuln = v
                break

        assert future_vuln is not None
        assert "under_investigation" in future_vuln["product_status"]

    def test_three_vulnerabilities_present(
        self, merged_sbom: Path, config_md: Path, trivy_results_file: Path, tmp_path: Path
    ) -> None:
        triage = parse_triage(config_md)
        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage=triage,
            output_path=out,
            scan_results_path=trivy_results_file,
        )
        with out.open() as fh:
            doc = json.load(fh)

        assert len(doc["vulnerabilities"]) == 3

    def test_missing_sbom_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Product SBOM not found"):
            generate_vex(
                sbom_path=tmp_path / "nope.spdx.json",
                triage={},
                output_path=tmp_path / "vex.json",
                scan_results_path=tmp_path / "also-nope.json",
            )

    def test_missing_scan_results_raises(
        self, merged_sbom: Path, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError, match="Scan results file not found"):
            generate_vex(
                sbom_path=merged_sbom,
                triage={},
                output_path=tmp_path / "vex.json",
                scan_results_path=tmp_path / "missing.json",
            )

    def test_empty_scan_results_produces_valid_csaf(
        self, merged_sbom: Path, tmp_path: Path
    ) -> None:
        """A scan with zero vulns should still produce a valid CSAF shell."""
        empty_results = tmp_path / "empty.json"
        empty_results.write_text(json.dumps({"Results": []}))

        out = tmp_path / "vex.csaf.json"
        generate_vex(
            sbom_path=merged_sbom,
            triage={},
            output_path=out,
            scan_results_path=empty_results,
        )
        with out.open() as fh:
            doc = json.load(fh)

        assert doc["document"]["csaf_version"] == "2.0"
        assert doc["vulnerabilities"] == []
