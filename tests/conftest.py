"""Shared test fixtures for cra-cli."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest  # type: ignore[import-untyped]


# ---------------------------------------------------------------------------
# Minimal Syft-style SPDX JSON fixtures
# ---------------------------------------------------------------------------

SBOM_FRONTEND = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "frontend",
    "documentNamespace": "https://anchore.com/syft/dir/frontend-abc123",
    "creationInfo": {
        "created": "2025-01-01T00:00:00Z",
        "creators": ["Tool: syft-1.0.0"],
        "licenseListVersion": "3.23",
    },
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-npm-react-18.2.0",
            "name": "react",
            "versionInfo": "18.2.0",
            "supplier": "Organization: Facebook",
            "downloadLocation": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/react@18.2.0",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-Package-npm-lodash-4.17.21",
            "name": "lodash",
            "versionInfo": "4.17.21",
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/lodash@4.17.21",
                }
            ],
        },
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-npm-react-18.2.0",
        },
        {
            "spdxElementId": "SPDXRef-Package-npm-react-18.2.0",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-npm-lodash-4.17.21",
        },
    ],
}

SBOM_BACKEND = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "backend",
    "documentNamespace": "https://anchore.com/syft/dir/backend-def456",
    "creationInfo": {
        "created": "2025-01-01T00:00:00Z",
        "creators": ["Tool: syft-1.0.0"],
        "licenseListVersion": "3.23",
    },
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-pypi-flask-3.0.0",
            "name": "flask",
            "versionInfo": "3.0.0",
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "BSD-3-Clause",
            "licenseDeclared": "BSD-3-Clause",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/flask@3.0.0",
                }
            ],
        },
        {
            # Deliberately shares the same lodash as Frontend — dedup test
            "SPDXID": "SPDXRef-Package-npm-lodash-4.17.21",
            "name": "lodash",
            "versionInfo": "4.17.21",
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/lodash@4.17.21",
                }
            ],
        },
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-pypi-flask-3.0.0",
        },
        {
            "spdxElementId": "SPDXRef-Package-pypi-flask-3.0.0",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-npm-lodash-4.17.21",
        },
    ],
}


# Trivy-style scan results fixture
TRIVY_RESULTS = {
    "Results": [
        {
            "Target": "product.spdx.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-44228",
                    "PkgName": "log4j-core",
                    "InstalledVersion": "2.14.1",
                    "FixedVersion": "2.17.0",
                    "Severity": "CRITICAL",
                    "Title": "Apache Log4j2 RCE",
                    "Description": "Apache Log4j2 JNDI features RCE vulnerability.",
                },
                {
                    "VulnerabilityID": "CVE-2023-44487",
                    "PkgName": "golang.org/x/net",
                    "InstalledVersion": "0.15.0",
                    "FixedVersion": "0.17.0",
                    "Severity": "HIGH",
                    "Title": "HTTP/2 Rapid Reset",
                    "Description": "HTTP/2 rapid reset attack.",
                },
                {
                    "VulnerabilityID": "CVE-2099-99999",
                    "PkgName": "somepkg",
                    "InstalledVersion": "1.0.0",
                    "Severity": "MEDIUM",
                    "Title": "Unknown future vuln",
                    "Description": "Not in triage — should default to under_investigation.",
                },
            ],
        }
    ]
}


PRODUCT_CONFIG_MD = textwrap.dedent("""\
    # Product Config

    ## SBOM Manifest

    | Component Name | Path            | Description      |
    |----------------|-----------------|------------------|
    | Frontend       | {frontend_path} | React dashboard  |
    | Backend        | {backend_path}  | Python API       |

    ## VEX Triage

    | CVE ID           | Status              | Justification                       | Impact                          |
    |------------------|----------------------|-------------------------------------|---------------------------------|
    | CVE-2021-44228   | known_not_affected   | vulnerable_code_not_in_execute_path | Log4j JNDI disabled             |
    | CVE-2023-44487   | known_affected       |                                     | HTTP/2 rapid reset — upgrading  |
""")


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sbom_files(tmp_path: Path) -> dict[str, Path]:
    """Write the two SPDX JSON fixtures to disk and return their paths."""
    frontend_path = tmp_path / "sboms" / "frontend.spdx.json"
    backend_path = tmp_path / "sboms" / "backend.spdx.json"
    frontend_path.parent.mkdir(parents=True, exist_ok=True)

    frontend_path.write_text(json.dumps(SBOM_FRONTEND, indent=2))
    backend_path.write_text(json.dumps(SBOM_BACKEND, indent=2))

    return {"frontend": frontend_path, "backend": backend_path}


@pytest.fixture()
def config_md(tmp_path: Path, sbom_files: dict[str, Path]) -> Path:
    """Write a product-config.md referencing the SBOM fixtures."""
    md_text = PRODUCT_CONFIG_MD.format(
        frontend_path=sbom_files["frontend"],
        backend_path=sbom_files["backend"],
    )
    config_path = tmp_path / "product-config.md"
    config_path.write_text(md_text)
    return config_path


@pytest.fixture()
def trivy_results_file(tmp_path: Path) -> Path:
    """Write fake Trivy scan results to disk."""
    path = tmp_path / "trivy-results.json"
    path.write_text(json.dumps(TRIVY_RESULTS, indent=2))
    return path


@pytest.fixture()
def merged_sbom(tmp_path: Path, config_md: Path) -> Path:
    """Run the merger and return the path to the product SBOM."""
    from src.config import parse_manifest
    from src.merger import merge_sboms

    manifest = parse_manifest(config_md)
    output = tmp_path / "product.spdx.json"
    merge_sboms(manifest=manifest, output_path=output)
    return output
