"""
main.py — CLI entry point for cra-cli.

Commands:
  cra aggregate   Merge multiple SPDX-JSON SBOMs into a Product SBOM.
  cra vex         Generate a CSAF 2.0 VEX document from the Product SBOM.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer  # type: ignore[import-untyped]
from rich import print as rprint  # type: ignore[import-untyped]

app = typer.Typer(
    name="cra",
    help=(
        "CRA-CLI — EU Cyber Resilience Act compliance tooling.\n\n"
        "Aggregate component SBOMs into a Product SBOM and generate "
        "CSAF 2.0 VEX documents."
    ),
    add_completion=False,
)


# ─── aggregate ────────────────────────────────────────────────────────────────

@app.command()
def aggregate(
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to product-config.md defining the SBOM manifest.",
        exists=False,  # we validate ourselves for a nicer message
    ),
    output: Path = typer.Option(
        Path("product.spdx.json"),
        "--output",
        "-o",
        help="Output path for the merged Product SBOM.",
    ),
    product_name: str = typer.Option(
        "Product",
        "--name",
        "-n",
        help="Product name to embed in the SPDX document.",
    ),
    product_version: str = typer.Option(
        "1.0",
        "--version",
        "-v",
        help="Product version string.",
    ),
    validate: bool = typer.Option(
        True,
        "--validate/--no-validate",
        help="Run spdx-tools validation on the merged SBOM.",
    ),
) -> None:
    """Merge multiple component SBOMs into one Product SBOM."""
    from src.config import parse_manifest
    from src.merger import merge_sboms, validate_spdx

    # --- Parse config ---
    try:
        manifest = parse_manifest(config)
    except FileNotFoundError:
        rprint(f"[red]✗[/red] Config file not found: {config}")
        raise typer.Exit(code=1)
    except ValueError as exc:
        rprint(f"[red]✗[/red] Config error: {exc}")
        raise typer.Exit(code=1)

    rprint(f"[blue]ℹ[/blue] Found {len(manifest)} component SBOM(s) in manifest.")

    # --- Merge ---
    try:
        result_path = merge_sboms(
            manifest=manifest,
            product_name=product_name,
            product_version=product_version,
            output_path=output,
        )
    except FileNotFoundError as exc:
        rprint(f"[red]✗[/red] {exc}")
        raise typer.Exit(code=1)

    rprint(f"[green]✓[/green] Product SBOM written to [bold]{result_path}[/bold]")

    # --- Validate ---
    if validate:
        rprint("[blue]ℹ[/blue] Running spdx-tools validation …")
        messages = validate_spdx(result_path)
        if messages:
            rprint(f"[yellow]⚠[/yellow] Validation produced {len(messages)} message(s):")
            for msg in messages[:20]:
                rprint(f"  • {msg}")
            if len(messages) > 20:
                rprint(f"  … and {len(messages) - 20} more.")
        else:
            rprint("[green]✓[/green] SPDX validation passed.")


# ─── vex ──────────────────────────────────────────────────────────────────────

@app.command()
def vex(
    sbom: Path = typer.Option(
        Path("product.spdx.json"),
        "--sbom",
        "-s",
        help="Path to the Product SBOM.",
    ),
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to product-config.md with the VEX Triage table.",
        exists=False,
    ),
    output: Path = typer.Option(
        Path("vex.csaf.json"),
        "--output",
        "-o",
        help="Output path for the CSAF 2.0 VEX document.",
    ),
    scan_results: Optional[Path] = typer.Option(
        None,
        "--scan-results",
        "-r",
        help=(
            "Path to pre-generated scanner results (JSON). "
            "If omitted, Trivy is invoked automatically."
        ),
    ),
    product_name: Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Product name.  Defaults to the SBOM document name.",
    ),
    product_version: str = typer.Option(
        "1.0",
        "--version",
        "-v",
        help="Product version.",
    ),
    vendor: str = typer.Option(
        "CRA-CLI-Vendor",
        "--vendor",
        help="Vendor name for the CSAF publisher.",
    ),
) -> None:
    """Generate a CSAF 2.0 VEX document from the Product SBOM."""
    from src.config import parse_triage
    from src.vex import generate_vex

    # --- Parse triage ---
    try:
        triage = parse_triage(config)
    except FileNotFoundError:
        rprint(f"[red]✗[/red] Config file not found: {config}")
        raise typer.Exit(code=1)
    except ValueError as exc:
        rprint(f"[red]✗[/red] Config error: {exc}")
        raise typer.Exit(code=1)

    rprint(f"[blue]ℹ[/blue] Loaded {len(triage)} triage rule(s) from config.")

    # --- Generate VEX ---
    try:
        result_path = generate_vex(
            sbom_path=sbom,
            triage=triage,
            output_path=output,
            scan_results_path=scan_results,
            product_name=product_name,
            product_version=product_version,
            vendor=vendor,
        )
    except FileNotFoundError as exc:
        rprint(f"[red]✗[/red] {exc}")
        raise typer.Exit(code=1)
    except RuntimeError as exc:
        rprint(f"[red]✗[/red] Scanner error: {exc}")
        raise typer.Exit(code=1)

    rprint(f"[green]✓[/green] VEX document written to [bold]{result_path}[/bold]")


# ─── entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
