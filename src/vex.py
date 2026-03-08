"""
vex.py — Generate a CSAF 2.0 VEX document.

Workflow:
  1. Scan the Product SBOM using an external scanner (Trivy by default)
     or accept a pre-generated scanner results JSON file.
  2. Load VEX triage overrides from product-config.md.
  3. Build the CSAF document via csaf-tool (anthonyharrison/csaf).
  4. Write vex.csaf.json.

The scanner is modular: users can plug in any tool that produces
JSON output (Trivy, Grype, Snyk, etc.) and pass the results directly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from csaf.generator import CSAFGenerator  # type: ignore[import-untyped]

from src.config import TriageEntry


# ---------------------------------------------------------------------------
# Scanner helpers
# ---------------------------------------------------------------------------

def run_trivy(sbom_path: str | Path) -> dict[str, Any]:
    """Run ``trivy sbom`` and return parsed JSON results.

    Raises
    ------
    FileNotFoundError – trivy not on PATH.
    RuntimeError      – trivy exits with a non-zero code.
    """
    sbom_path = str(Path(sbom_path).resolve())
    try:
        result = subprocess.run(
            ["trivy", "sbom", "--format", "json", sbom_path],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "trivy is not installed or not on PATH. "
            "Install it from https://aquasecurity.github.io/trivy/ "
            "or pass pre-generated scanner results via --scan-results."
        ) from None

    if result.returncode != 0:
        raise RuntimeError(
            f"trivy exited with code {result.returncode}:\n{result.stderr}"
        )

    return json.loads(result.stdout)


def load_scan_results(path: str | Path) -> dict[str, Any]:
    """Load pre-generated scanner results from a JSON file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Scan results file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_vulnerabilities(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize Trivy (or compatible) JSON into a flat list of findings.

    Each item has at least:
      - VulnerabilityID (str)
      - PkgName (str)
      - InstalledVersion (str)
      - Severity (str)
      - Description (str, may be empty)
    """
    vulns: list[dict[str, Any]] = []
    # Trivy wraps findings under "Results"
    for result_block in scan_data.get("Results", []):
        for v in result_block.get("Vulnerabilities", []):
            vulns.append(v)

    # Fallback: some scanners put vulns at top level
    if not vulns and "vulnerabilities" in scan_data:
        vulns = scan_data["vulnerabilities"]

    return vulns


# ---------------------------------------------------------------------------
# SBOM package extraction helpers
# ---------------------------------------------------------------------------

def _extract_packages_from_sbom(sbom_path: str | Path) -> dict[str, dict[str, Any]]:
    """Read the product SBOM and return a dict keyed by package name.

    Each value contains 'name', 'version', 'purl' (if available).
    This is used to populate the CSAF product tree.
    """
    sbom_path = Path(sbom_path)
    if not sbom_path.exists():
        raise FileNotFoundError(f"Product SBOM not found: {sbom_path}")

    with sbom_path.open(encoding="utf-8") as fh:
        sbom = json.load(fh)

    packages: dict[str, dict[str, Any]] = {}
    for pkg in sbom.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        key = f"{name}@{version}"
        packages[key] = {
            "name": name,
            "version": version,
            "purl": purl,
            "spdxid": pkg.get("SPDXID", ""),
        }
    return packages


def _sbom_product_name(sbom_path: str | Path) -> str:
    """Extract the document name from the SBOM."""
    with Path(sbom_path).open(encoding="utf-8") as fh:
        sbom = json.load(fh)
    return sbom.get("name", "Product")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_vex(
    sbom_path: str | Path,
    triage: dict[str, TriageEntry],
    output_path: str | Path = "vex.csaf.json",
    *,
    scan_results_path: str | Path | None = None,
    product_name: str | None = None,
    product_version: str = "1.0",
    vendor: str = "CRA-CLI-Vendor",
    csaf_config: str = "",
    document_id: str = "",
    document_title: str = "",
) -> Path:
    """Generate a CSAF 2.0 VEX document.

    Parameters
    ----------
    sbom_path:
        Path to the Product SBOM (product.spdx.json).
    triage:
        Triage map from ``config.parse_triage()`` — CVE ID → TriageEntry.
    output_path:
        Where to write the VEX document.
    scan_results_path:
        If provided, load scan results from this file instead of running
        Trivy.  Allows users to plug in any scanner.
    product_name:
        Name for the CSAF product tree.  Defaults to the SBOM document name.
    product_version:
        Product release version.
    vendor:
        Vendor name for CSAF product tree.
    csaf_config:
        Path to a csaf.ini configuration file (optional).
    document_id:
        CSAF document identifier.
    document_title:
        CSAF document title / header.

    Returns
    -------
    Path to the written VEX file.
    """
    sbom_path = Path(sbom_path)
    output_path = Path(output_path)

    if not sbom_path.exists():
        raise FileNotFoundError(f"Product SBOM not found: {sbom_path}")

    # ---- 1. Obtain vulnerability scan results ----
    if scan_results_path is not None:
        scan_data = load_scan_results(scan_results_path)
    else:
        scan_data = run_trivy(sbom_path)

    findings = _extract_vulnerabilities(scan_data)

    # ---- 2. Determine product identity ----
    if product_name is None:
        product_name = _sbom_product_name(sbom_path)

    # ---- 3. Build CSAF document via csaf-tool ----
    csaf_gen = CSAFGenerator(csaf_config)

    if document_title:
        csaf_gen.set_header_title(document_title)
    else:
        csaf_gen.set_header_title(f"{product_name} {product_version} VEX Document")

    if document_id:
        csaf_gen.set_id(document_id)
    else:
        csaf_gen.set_id(f"{product_name}-{product_version}-VEX")

    csaf_gen.set_title(
        f"Vulnerability Exploitability eXchange for {product_name} {product_version}"
    )

    csaf_gen.set_value("status", "draft")
    csaf_gen.set_value("author", vendor)
    csaf_gen.set_value("author_url", f"https://{vendor.lower().replace(' ', '-')}.example.com")

    # ---- 4. Add the product to the CSAF product tree ----
    csaf_gen.add_product(
        product_name=product_name,
        vendor=vendor,
        release=product_version,
        sbom=str(sbom_path.resolve()),
    )

    # ---- 5. Map scanner findings to CSAF vulnerabilities ----
    if not findings:
        # No vulns found — still produce a valid (empty-vulns) CSAF doc
        print("[cra-cli] No vulnerabilities found by scanner.", file=sys.stderr)

    for finding in findings:
        cve_id = finding.get("VulnerabilityID", finding.get("id", ""))
        pkg_name = finding.get("PkgName", finding.get("package", ""))
        description = finding.get("Description", finding.get("description", ""))
        if not description:
            description = finding.get("Title", finding.get("title", "Not available"))

        # Determine status & justification from triage map
        triage_entry = triage.get(cve_id)
        if triage_entry is not None:
            status = triage_entry.status
            justification = triage_entry.justification or None
            comment = triage_entry.impact or None
        else:
            status = "under_investigation"
            justification = None
            comment = None

        csaf_gen.add_vulnerability(
            product_name=product_name,
            release=product_version,
            id=cve_id,
            description=description,
            status=status,
            comment=comment,
            justification=justification,
        )

    # ---- 6. Generate & publish ----
    csaf_gen.generate_csaf()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    csaf_gen.publish_csaf(str(output_path))

    # ---- 7. Structural sanity check ----
    _validate_csaf_structure(output_path)

    return output_path


def _validate_csaf_structure(path: Path) -> None:
    """Quick structural validation against the OASIS CSAF 2.0 VEX schema.

    Prints warnings to stderr; does not raise.
    """
    with path.open(encoding="utf-8") as fh:
        doc = json.load(fh)

    required_top = {"document", "product_tree", "vulnerabilities"}
    missing_top = required_top - set(doc.keys())
    if missing_top:
        print(
            f"[cra-cli] WARNING: CSAF missing top-level keys: {missing_top}",
            file=sys.stderr,
        )
        return

    # Document section checks
    doc_section = doc["document"]
    if doc_section.get("csaf_version") != "2.0":
        print("[cra-cli] WARNING: csaf_version is not '2.0'", file=sys.stderr)
    if doc_section.get("category") != "csaf_vex":
        print("[cra-cli] WARNING: category is not 'csaf_vex'", file=sys.stderr)
    if "tracking" not in doc_section:
        print("[cra-cli] WARNING: 'tracking' missing from document", file=sys.stderr)
    if "publisher" not in doc_section:
        print("[cra-cli] WARNING: 'publisher' missing from document", file=sys.stderr)

    # Product tree checks
    pt = doc["product_tree"]
    if "branches" not in pt or len(pt["branches"]) == 0:
        print("[cra-cli] WARNING: product_tree has no branches", file=sys.stderr)
