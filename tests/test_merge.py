"""Tests for the SBOM merger (src/merger.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest  # type: ignore[import-untyped]

from src.config import parse_manifest
from src.merger import merge_sboms


class TestMergeSBOMs:
    """Verify merging logic: namespacing, dedup, relationships."""

    def test_merged_file_is_written(self, config_md: Path, tmp_path: Path) -> None:
        manifest = parse_manifest(config_md)
        out = tmp_path / "product.spdx.json"
        result = merge_sboms(manifest=manifest, output_path=out)
        assert result.exists()

    def test_merged_is_valid_json(self, merged_sbom: Path) -> None:
        with merged_sbom.open() as fh:
            data = json.load(fh)
        assert data["spdxVersion"] == "SPDX-2.3"
        assert data["SPDXID"] == "SPDXRef-DOCUMENT"

    def test_product_root_package_present(self, merged_sbom: Path) -> None:
        with merged_sbom.open() as fh:
            data = json.load(fh)
        names = [p["name"] for p in data["packages"]]
        assert "Product" in names  # the virtual product root

    def test_spdxids_are_namespaced(self, merged_sbom: Path) -> None:
        """Every component package SPDXID must carry its prefix."""
        with merged_sbom.open() as fh:
            data = json.load(fh)
        component_ids = [
            p["SPDXID"]
            for p in data["packages"]
            if p["SPDXID"] != "SPDXRef-Product-Root"
        ]
        for sid in component_ids:
            assert sid.startswith("SPDXRef-Frontend-") or sid.startswith(
                "SPDXRef-Backend-"
            ), f"SPDXID not namespaced: {sid}"

    def test_no_duplicate_spdxids(self, merged_sbom: Path) -> None:
        with merged_sbom.open() as fh:
            data = json.load(fh)
        ids = [p["SPDXID"] for p in data["packages"]]
        assert len(ids) == len(set(ids)), f"Duplicate SPDXIDs found: {ids}"

    def test_lodash_deduplicated(self, merged_sbom: Path) -> None:
        """Both SBOMs contain lodash@4.17.21 — only one should survive."""
        with merged_sbom.open() as fh:
            data = json.load(fh)
        lodash_pkgs = [
            p for p in data["packages"] if p["name"] == "lodash"
        ]
        assert len(lodash_pkgs) == 1, (
            f"Expected 1 lodash package, found {len(lodash_pkgs)}"
        )

    def test_describes_relationships_present(self, merged_sbom: Path) -> None:
        """Master document should DESCRIBE the component roots."""
        with merged_sbom.open() as fh:
            data = json.load(fh)
        describes = [
            r
            for r in data["relationships"]
            if r["spdxElementId"] == "SPDXRef-DOCUMENT"
            and r["relationshipType"] == "DESCRIBES"
        ]
        # At least: Product-Root + 2 component roots
        assert len(describes) >= 3

    def test_depends_on_from_product_root(self, merged_sbom: Path) -> None:
        with merged_sbom.open() as fh:
            data = json.load(fh)
        depends = [
            r
            for r in data["relationships"]
            if r["spdxElementId"] == "SPDXRef-Product-Root"
            and r["relationshipType"] == "DEPENDS_ON"
        ]
        assert len(depends) == 2  # Frontend root + Backend root

    def test_missing_sbom_raises(self, tmp_path: Path) -> None:
        from src.config import ManifestEntry

        manifest = [
            ManifestEntry(
                component_name="Ghost",
                path=str(tmp_path / "nonexistent.spdx.json"),
                description="Does not exist",
            )
        ]
        with pytest.raises(FileNotFoundError, match="Component SBOM not found"):
            merge_sboms(manifest=manifest, output_path=tmp_path / "out.json")

    def test_relationship_ids_are_remapped(self, merged_sbom: Path) -> None:
        """Relationships should not reference SPDXIDs that were deduped away."""
        with merged_sbom.open() as fh:
            data = json.load(fh)
        all_pkg_ids = {p["SPDXID"] for p in data["packages"]}
        all_pkg_ids.add("SPDXRef-DOCUMENT")  # the document itself
        for rel in data["relationships"]:
            assert rel["spdxElementId"] in all_pkg_ids or rel["spdxElementId"] == "SPDXRef-DOCUMENT", (
                f"Dangling spdxElementId: {rel['spdxElementId']}"
            )
            assert rel["relatedSpdxElement"] in all_pkg_ids or rel["relatedSpdxElement"] == "SPDXRef-DOCUMENT", (
                f"Dangling relatedSpdxElement: {rel['relatedSpdxElement']}"
            )
