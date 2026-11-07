# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        src.lh_cloud_posture.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-cloud-posture.

Implements CLI commands:
- lh-cloud scan <path> [--format table|json|sarif] [--output <path>]
                       [--min-severity <level>] [--fail-on <level>]
- lh-cloud rules
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from lh_cloud_posture.cloudformation_scanner import scan_cloudformation
from lh_cloud_posture.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_cloud_posture.k8s_scanner import scan_kubernetes
from lh_cloud_posture.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)
from lh_cloud_posture.terraform_scanner import scan_terraform

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-cloud",
    help=(
        "Enterprise cloud security posture analyzer and IaC auditor.\n"
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    no_args_is_help=True,
    rich_markup_mode=None,
)
console = Console()


def _is_terraform_file(path: Path) -> bool:
    """Check if file is a Terraform configuration."""
    name = path.name.lower()
    if name.endswith((".tf", ".tf.json")):
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")[:500]
        if 'resource "' in content or "terraform {" in content or '"resource":' in content:
            return True
    except (OSError, UnicodeDecodeError):
        return False
    return False


def _is_k8s_file(path: Path) -> bool:
    """Check if file is a Kubernetes manifest."""
    name = path.name.lower()
    if name.endswith((".yaml", ".yml", ".json")):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:600]
            if "apiVersion:" in content and "kind:" in content:
                return True
        except (OSError, UnicodeDecodeError):
            return False
    return False


def _is_cloudformation_file(path: Path) -> bool:
    """Check if file is an AWS CloudFormation template."""
    name = path.name.lower()
    if "cloudformation" in name or name.endswith(".template") or name.endswith(".cf.yaml"):
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")[:600]
        if "AWSTemplateFormatVersion" in content or "AWS::" in content:
            return True
    except (OSError, UnicodeDecodeError):
        return False
    return False


def _discover_and_scan(target_path: Path) -> list[ScanTargetResult]:
    """Scan target path (file or recursively in directory)."""
    results: list[ScanTargetResult] = []

    if target_path.is_file():
        if _is_terraform_file(target_path):
            results.append(scan_terraform(target_path))
        elif _is_cloudformation_file(target_path):
            results.append(scan_cloudformation(target_path))
        elif _is_k8s_file(target_path):
            results.append(scan_kubernetes(target_path))
        else:
            # Fallback heuristic
            try:
                head = target_path.read_text(encoding="utf-8", errors="ignore")[:500]
                if "AWSTemplateFormatVersion" in head or "AWS::" in head:
                    results.append(scan_cloudformation(target_path))
                elif "apiVersion:" in head and "kind:" in head:
                    results.append(scan_kubernetes(target_path))
                else:
                    results.append(scan_terraform(target_path))
            except Exception as e:
                results.append(
                    ScanTargetResult(
                        target=str(target_path),
                        target_type=TargetType.TERRAFORM,
                        findings=[],
                        error_message=f"Could not read target file: {e}",
                    )
                )
        return results

    # Directory scanning
    found_targets = False

    # Terraform files
    tf_files = list(target_path.rglob("*.tf")) + list(target_path.rglob("*.tf.json"))
    for tf in sorted(set(tf_files)):
        if tf.is_file() and not any(part.startswith(".") for part in tf.parts):
            results.append(scan_terraform(tf))
            found_targets = True

    # YAML/YML files (Kubernetes and CloudFormation)
    yaml_files = list(target_path.rglob("*.yaml")) + list(target_path.rglob("*.yml"))
    for yf in sorted(set(yaml_files)):
        if yf.is_file() and not any(part.startswith(".") for part in yf.parts):
            if _is_cloudformation_file(yf):
                results.append(scan_cloudformation(yf))
                found_targets = True
            elif _is_k8s_file(yf):
                results.append(scan_kubernetes(yf))
                found_targets = True

    # CloudFormation .template files
    cf_files = list(target_path.rglob("*.template"))
    for cf in sorted(set(cf_files)):
        if cf.is_file() and not any(part.startswith(".") for part in cf.parts):
            results.append(scan_cloudformation(cf))
            found_targets = True

    if not found_targets:
        results.append(
            ScanTargetResult(
                target=str(target_path),
                target_type=TargetType.TERRAFORM,
                findings=[],
                error_message="No Terraform, Kubernetes, or CloudFormation artifacts discovered.",
            )
        )

    return results


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Path | None,
) -> None:
    """Format and write or print the audit report according to format and destination."""
    report.compute_summary()

    if fmt == OutputFormat.JSON:
        rendered = export_json(report)
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(report)
    else:
        # Table format
        if output_path:
            file_console = Console(record=True, width=120, color_system=None)
            render_table_report(report, console=file_console)
            rendered = file_console.export_text()
        else:
            render_table_report(report, console=console)
            rendered = ""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Report successfully written to {output_path}[/bold green]")
    elif rendered:
        print(rendered)


@app.command(name="scan")
def scan(
    path: Annotated[
        str,
        typer.Argument(
            help="Path to Terraform (.tf), Kubernetes (.yaml), CloudFormation, or directory."
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
    min_severity: Annotated[
        FindingSeverity | None,
        typer.Option("--min-severity", "-s", help="Filter findings below this severity."),
    ] = None,
    fail_on: Annotated[
        FindingSeverity | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for failure exit (CRITICAL, HIGH, MEDIUM, LOW, INFO).",
        ),
    ] = FindingSeverity.HIGH,
) -> None:
    """Scan cloud IaC artifacts for security misconfigurations and posture violations."""
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[bold red]Error: Target path '{path}' does not exist.[/bold red]")
        raise typer.Exit(code=2)

    results = _discover_and_scan(target_path)

    report = AuditReport(
        report_type="cloud_posture",
        generated_at=datetime.now(UTC),
        parameters={
            "path": path,
            "format": format.value,
            "min_severity": min_severity.value if min_severity else None,
            "fail_on": fail_on.value if fail_on else None,
        },
        results=results,
    )

    if min_severity is not None:
        report.filter_min_severity(min_severity)

    _output_report(report, format, output)

    if report.has_failures(fail_on):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="rules")
def rules() -> None:
    """List all supported LH-CLOUD security posture detection rules."""
    table = Table(
        title="LH-CLOUD Posture Detection Rules",
        border_style="blue",
    )
    table.add_column("Rule ID", style="bold magenta", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Category", style="cyan")
    table.add_column("Rule Title", style="bold white")
    table.add_column("Targets")
    table.add_column("Description")

    sev_styles = {
        FindingSeverity.CRITICAL: "bold white on red",
        FindingSeverity.HIGH: "bold red",
        FindingSeverity.MEDIUM: "bold yellow",
        FindingSeverity.LOW: "bold cyan",
        FindingSeverity.INFO: "bold blue",
    }

    for rule_id, rule_def in sorted(RULES_REGISTRY.items()):
        badge = Text(rule_def.severity.value, style=sev_styles.get(rule_def.severity, "bold"))
        targets_str = ", ".join(t.value for t in rule_def.target_types)
        table.add_row(
            rule_id,
            badge,
            rule_def.category.value,
            rule_def.title,
            targets_str,
            rule_def.description,
        )

    console.print(table)


if __name__ == "__main__":
    app()
