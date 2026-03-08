"""
merger.py — Aggregate multiple Syft SPDX-JSON SBOMs into a single Product SBOM.

Hybrid approach:
  • Raw JSON manipulation for SPDXID namespace-prefixing & deduplication.
  • spdx-tools for final validation.

Key invariants
--------------
1. Every SPDXID from a component SBOM is prefixed with the component name
   so that two SBOMs both containing ``SPDXRef-Package-pip-requests-2.31.0``
   won't collide.
2. Packages are deduplicated by (name, versionInfo, first-purl-found).
3. The master document's ``SPDXRef-DOCUMENT`` has a ``DESCRIBES`` relationship
   to each component's root package.
"""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import ManifestEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _purl_from_package(pkg: dict[str, Any]) -> str | None:
    """Extract the first purl from a package's externalRefs, if any."""
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def _dedup_key(pkg: dict[str, Any]) -> tuple[str, str, str | None]:
    """Return a deduplication key for a package: (name, version, purl)."""
    return (
        pkg.get("name", ""),
        pkg.get("versionInfo", ""),
        _purl_from_package(pkg),
    )


def _prefix_spdxid(spdxid: str, prefix: str) -> str:
    """Prefix an SPDXID while keeping the ``SPDXRef-`` leader.

    ``SPDXRef-Package-foo`` → ``SPDXRef-<prefix>-Package-foo``
    """
    if spdxid.startswith("SPDXRef-"):
        return f"SPDXRef-{prefix}-{spdxid[8:]}"
    return f"{prefix}-{spdxid}"


def _namespace_component(
    sbom: dict[str, Any],
    prefix: str,
) -> dict[str, Any]:
    """Return a deep copy of *sbom* with all SPDXIDs prefixed.

    Rewrites ``SPDXID`` on every package and file, and both sides of every
    relationship.  The document's own ``SPDXRef-DOCUMENT`` is also prefixed.
    """
    sbom = copy.deepcopy(sbom)

    # Packages
    for pkg in sbom.get("packages", []):
        pkg["SPDXID"] = _prefix_spdxid(pkg["SPDXID"], prefix)

    # Files
    for f in sbom.get("files", []):
        f["SPDXID"] = _prefix_spdxid(f["SPDXID"], prefix)

    # Relationships
    for rel in sbom.get("relationships", []):
        rel["spdxElementId"] = _prefix_spdxid(rel["spdxElementId"], prefix)
        rel["relatedSpdxElement"] = _prefix_spdxid(rel["relatedSpdxElement"], prefix)

    # Document SPDXID itself
    sbom["SPDXID"] = _prefix_spdxid(sbom.get("SPDXID", "SPDXRef-DOCUMENT"), prefix)

    return sbom


def _find_root_package(sbom: dict[str, Any]) -> str | None:
    """Find the root package SPDXID — the one the document DESCRIBES."""
    doc_id = sbom.get("SPDXID", "")
    for rel in sbom.get("relationships", []):
        if (
            rel.get("spdxElementId") == doc_id
            and rel.get("relationshipType") == "DESCRIBES"
        ):
            return rel["relatedSpdxElement"]
    # Fallback: first package
    pkgs = sbom.get("packages", [])
    if pkgs:
        return pkgs[0]["SPDXID"]
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def merge_sboms(
    manifest: list[ManifestEntry],
    product_name: str = "Product",
    product_version: str = "1.0",
    output_path: str | Path = "product.spdx.json",
    *,
    supplier: str = "Organization: CRA-CLI",
) -> Path:
    """Merge component SBOMs listed in *manifest* into one Product SBOM.

    Parameters
    ----------
    manifest:
        List of ``ManifestEntry`` with ``component_name`` and ``path``.
    product_name:
        Name for the product-level SPDX document.
    product_version:
        Version string for the product package.
    output_path:
        Where to write the merged ``product.spdx.json``.
    supplier:
        Supplier field for the master document.

    Returns
    -------
    Path to the written file.

    Raises
    ------
    FileNotFoundError – if a component SBOM path does not exist.
    json.JSONDecodeError – if a component SBOM is not valid JSON.
    """
    output_path = Path(output_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_namespace = (
        f"https://cra-cli.local/spdx/{product_name}-{product_version}"
        f"-{uuid.uuid4()}"
    )

    # ---- Master SPDX document skeleton ----
    master: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": product_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": now,
            "creators": [
                "Tool: cra-cli-0.1.0",
                supplier,
            ],
            "licenseListVersion": "3.23",
        },
        "packages": [],
        "files": [],
        "relationships": [],
    }

    # Create a virtual "product root package" that the document DESCRIBES.
    product_root_id = "SPDXRef-Product-Root"
    product_root_pkg: dict[str, Any] = {
        "SPDXID": product_root_id,
        "name": product_name,
        "versionInfo": product_version,
        "supplier": supplier,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    master["packages"].append(product_root_pkg)
    master["relationships"].append(
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": product_root_id,
        }
    )

    # ---- Dedup tracking ----
    seen_packages: dict[tuple[str, str, str | None], str] = {}  # key → SPDXID kept
    # Track SPDXID rewrites caused by dedup so relationships can be patched.
    id_remap: dict[str, str] = {}

    # ---- Iterate component SBOMs ----
    for entry in manifest:
        sbom_path = Path(entry.path)
        if not sbom_path.exists():
            raise FileNotFoundError(
                f"Component SBOM not found: {sbom_path} "
                f"(component: {entry.component_name})"
            )

        with sbom_path.open(encoding="utf-8") as fh:
            raw_sbom: dict[str, Any] = json.load(fh)

        prefix = entry.component_name.replace(" ", "-")
        ns_sbom = _namespace_component(raw_sbom, prefix)

        # Locate the root package *after* namespacing.
        root_id = _find_root_package(ns_sbom)

        # -- Merge packages (with dedup) --
        for pkg in ns_sbom.get("packages", []):
            key = _dedup_key(pkg)
            existing_id = seen_packages.get(key)
            if existing_id is not None:
                # Duplicate → record remap so relationships point to the kept ID.
                id_remap[pkg["SPDXID"]] = existing_id
            else:
                seen_packages[key] = pkg["SPDXID"]
                master["packages"].append(pkg)

        # -- Merge files --
        seen_file_ids: set[str] = {f["SPDXID"] for f in master["files"]}
        for f in ns_sbom.get("files", []):
            if f["SPDXID"] not in seen_file_ids:
                master["files"].append(f)
                seen_file_ids.add(f["SPDXID"])

        # -- Merge relationships (skip component-level DESCRIBES; we add our own) --
        comp_doc_id = ns_sbom.get("SPDXID", "")
        for rel in ns_sbom.get("relationships", []):
            if (
                rel.get("spdxElementId") == comp_doc_id
                and rel.get("relationshipType") == "DESCRIBES"
            ):
                continue  # replaced by master DESCRIBES → root_id
            master["relationships"].append(rel)

        # -- Link product root → component root --
        if root_id:
            # Resolve possible remap
            resolved_root = id_remap.get(root_id, root_id)
            master["relationships"].append(
                {
                    "spdxElementId": product_root_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": resolved_root,
                }
            )
            # Also add a DESCRIBES from Document to the component root
            master["relationships"].append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": resolved_root,
                }
            )

    # ---- Apply id_remap to all relationships ----
    for rel in master["relationships"]:
        rel["spdxElementId"] = id_remap.get(
            rel["spdxElementId"], rel["spdxElementId"]
        )
        rel["relatedSpdxElement"] = id_remap.get(
            rel["relatedSpdxElement"], rel["relatedSpdxElement"]
        )

    # ---- Remove files list if empty (keeps output clean) ----
    if not master["files"]:
        del master["files"]

    # ---- Write output ----
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(master, fh, indent=2)

    return output_path


# ---------------------------------------------------------------------------
# Validation helper (optional – called from CLI)
# ---------------------------------------------------------------------------

def validate_spdx(path: str | Path) -> list[str]:
    """Validate an SPDX JSON file using spdx-tools.

    Returns a list of human-readable validation messages.
    An empty list means the document is valid.
    """
    try:
        from spdx_tools.spdx.parser.parse_anything import parse_file  # type: ignore[import-untyped]
        from spdx_tools.spdx.validation.document_validator import (  # type: ignore[import-untyped]
            validate_full_spdx_document,
        )

        doc = parse_file(str(path))
        messages = validate_full_spdx_document(doc)
        return [
            f"[{m.context}] {m.validation_message}" for m in messages
        ]
    except Exception as exc:  # noqa: BLE001
        return [f"Validation could not run: {exc}"]
