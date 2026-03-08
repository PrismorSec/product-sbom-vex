"""
config.py — Parse product-config.md using markdown-it-py.

Extracts two tables:
  1. SBOM Manifest  (component_name, path, description)
  2. VEX Triage     (cve_id → {status, justification, impact})

No regex is used; we rely on markdown-it-py's token stream.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from markdown_it import MarkdownIt  # type: ignore[import-untyped]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ManifestEntry:
    """One row from the SBOM Manifest table."""

    component_name: str
    path: str
    description: str


@dataclasses.dataclass
class TriageEntry:
    """One row from the VEX Triage table."""

    cve_id: str
    status: str
    justification: str
    impact: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_tables(md_text: str) -> dict[str, list[list[str]]]:
    """Return a mapping of *preceding heading text* → table rows.

    Each table row is a list of cell strings (stripped).
    The first row is the header row.
    """
    md = MarkdownIt("commonmark").enable("table")
    tokens = md.parse(md_text)

    tables: dict[str, list[list[str]]] = {}
    current_heading: str | None = None
    i = 0

    while i < len(tokens):
        tok = tokens[i]

        # Track headings so we can key tables by section title.
        if tok.type == "heading_open":
            # The inline content is the next token.
            i += 1
            if i < len(tokens) and tokens[i].type == "inline":
                current_heading = tokens[i].content.strip()
            i += 1  # skip heading_close
            continue

        # Collect table rows when we hit table_open.
        if tok.type == "table_open" and current_heading is not None:
            rows: list[list[str]] = []
            i += 1  # move past table_open
            while i < len(tokens) and tokens[i].type != "table_close":
                if tokens[i].type == "tr_open":
                    cells: list[str] = []
                    i += 1  # move past tr_open
                    while i < len(tokens) and tokens[i].type != "tr_close":
                        if tokens[i].type in ("th_open", "td_open"):
                            i += 1  # move to inline content
                            if i < len(tokens) and tokens[i].type == "inline":
                                cells.append(tokens[i].content.strip())
                                i += 1  # move past inline
                            # now we should be at th_close / td_close
                            if i < len(tokens) and tokens[i].type in ("th_close", "td_close"):
                                i += 1  # move past th_close / td_close
                        else:
                            i += 1
                    rows.append(cells)
                i += 1  # move past tr_close or thead_open/close, tbody_open/close
            tables[current_heading] = rows
            i += 1  # move past table_close
            continue

        i += 1

    return tables


def _table_to_dicts(
    rows: list[list[str]],
) -> list[dict[str, str]]:
    """Convert a header + data-rows structure into a list of dicts."""
    if not rows:
        return []
    headers = [h.strip().lower().replace(" ", "_") for h in rows[0]]
    result = []
    for cell_row in rows[1:]:
        row_dict: dict[str, str] = {}
        for j, header in enumerate(headers):
            if j < len(cell_row):
                row_dict[header] = cell_row[j].strip()
            else:
                row_dict[header] = ""
        result.append(row_dict)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_config(config_path: str | Path) -> dict[str, Any]:
    """Parse *product-config.md* and return both tables.

    Returns
    -------
    dict with keys ``"manifest"`` (list[ManifestEntry]) and
    ``"triage"`` (dict[str, TriageEntry] keyed by CVE ID).

    Raises
    ------
    FileNotFoundError  – config file missing.
    ValueError         – required section / columns missing.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    md_text = config_path.read_text(encoding="utf-8")
    tables = _extract_tables(md_text)

    # ---- SBOM Manifest ----
    manifest_rows = None
    for key in tables:
        if "manifest" in key.lower() or "sbom" in key.lower():
            manifest_rows = tables[key]
            break
    if manifest_rows is None:
        raise ValueError(
            "product-config.md must contain an '## SBOM Manifest' section with a table."
        )

    manifest_dicts = _table_to_dicts(manifest_rows)
    required_manifest_cols = {"component_name", "path"}
    for row in manifest_dicts:
        if not required_manifest_cols.issubset(row.keys()):
            raise ValueError(
                f"SBOM Manifest table must have columns: {required_manifest_cols}. "
                f"Found: {set(row.keys())}"
            )

    manifest = [
        ManifestEntry(
            component_name=r["component_name"],
            path=r["path"],
            description=r.get("description", ""),
        )
        for r in manifest_dicts
    ]

    # ---- VEX Triage ----
    triage_rows = None
    for key in tables:
        if "triage" in key.lower() or "vex" in key.lower():
            triage_rows = tables[key]
            break

    triage: dict[str, TriageEntry] = {}
    if triage_rows is not None:
        triage_dicts = _table_to_dicts(triage_rows)
        required_triage_cols = {"cve_id", "status"}
        for row in triage_dicts:
            if not required_triage_cols.issubset(row.keys()):
                raise ValueError(
                    f"VEX Triage table must have columns: {required_triage_cols}. "
                    f"Found: {set(row.keys())}"
                )
            entry = TriageEntry(
                cve_id=row["cve_id"],
                status=row["status"],
                justification=row.get("justification", ""),
                impact=row.get("impact", ""),
            )
            triage[entry.cve_id] = entry

    return {"manifest": manifest, "triage": triage}


def parse_manifest(config_path: str | Path) -> list[ManifestEntry]:
    """Convenience: return only the SBOM manifest entries."""
    return parse_config(config_path)["manifest"]


def parse_triage(config_path: str | Path) -> dict[str, TriageEntry]:
    """Convenience: return only the VEX triage map (CVE → TriageEntry)."""
    return parse_config(config_path)["triage"]
