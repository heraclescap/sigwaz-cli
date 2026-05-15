#!/usr/bin/env python3
"""
SigWaz CLI — Sigma → Wazuh rule converter.

Commands:
  convert   Convert a single Sigma YAML rule to Wazuh XML
  batch     Batch-convert a directory or multi-doc YAML file
  check     Validate an existing Wazuh XML rules file
  info      Show version info and supported products
  fieldmaps Display Sigma → Wazuh field mapping tables
  sidmaps   Display parent rule ID (if_sid) mappings per product

Quick start:
  sigwaz convert rule.yml -o rule_rules.xml
  sigwaz batch rules/ -o output/ --split 50 --min-level medium
  sigwaz batch rules.yml -o output/ --excluded-statuses experimental,deprecated
  sigwaz batch rules.zip -o output/ --split 50
  sigwaz batch rules/ -o output/ --config ~/.sigwaz/config.yaml
  sigwaz check wazuh_rules.xml
  sigwaz info
"""
from __future__ import annotations
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.theme import Theme

# Try standalone layout (sigwaz/ package, public CLI repo) first
try:
    from sigwaz.converter import ConversionConfig, convert_single, convert_batch, merge_results_xml
    from sigwaz.field_maps import list_products, FIELD_MAPS
    from sigwaz.sid_maps import IF_SID_MAP, IF_GROUP_MAP
    from sigwaz.utils.id_tracker import IDTracker
    from sigwaz.utils.xml_validator import validate_xml
    from sigwaz.utils.splitter import split_xml, filename_for_chunk
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.core.converter import ConversionConfig, convert_single, convert_batch, merge_results_xml
    from app.core.field_maps import list_products, FIELD_MAPS
    from app.core.sid_maps import IF_SID_MAP, IF_GROUP_MAP
    from app.utils.id_tracker import IDTracker
    from app.utils.xml_validator import validate_xml
    from app.utils.splitter import split_xml, filename_for_chunk

__version__ = "1.0.0"

# ── Theme ─────────────────────────────────────────────────────────────────────

SIGWAZ_THEME = Theme({
    "accent":    "bold cyan",
    "accent2":   "bold bright_cyan",
    "success":   "bold green",
    "warning":   "bold yellow",
    "error":     "bold red",
    "muted":     "dim white",
    "rule_id":   "bold magenta",
    "mitre":     "bold yellow",
    "level.informational": "dim white",
    "level.low":           "green",
    "level.medium":        "yellow",
    "level.high":          "orange1",
    "level.critical":      "bold red",
})

console = Console(theme=SIGWAZ_THEME, highlight=False)

app = typer.Typer(
    name="sigwaz",
    help=(
        "[bold cyan]SigWaz[/bold cyan] [dim]v{v}[/dim] — Sigma → Wazuh rule converter\n\n"
        "Convert Sigma detection rules to production-ready Wazuh XML.\n"
        "Supports single rules, multi-doc YAML, and full directory batch processing.\n\n"
        "[dim]Run [bold]sigwaz <command> --help[/bold] for detailed option docs.[/dim]"
    ).format(v=__version__),
    rich_markup_mode="rich",
    add_completion=False,
    no_args_is_help=True,
)


# ── Hardcoded defaults (used for CLI/config resolution) ──────────────────────
_DEFAULTS: Dict[str, Any] = {
    "rule_id_start":        900000,
    "no_full_log":          True,
    "email_alert":          False,
    "email_levels":         "critical,high",
    "process_experimental": True,
    "excluded_statuses":    "experimental,test,deprecated,unsupported",
    "min_level":            "",
    "allowed_products":     "",
    "sigma_guid_email":     "",
    "rules_link_base":      "https://github.com/SigmaHQ/sigma/tree/master/rules",
    "split_size":           50,
    "id_file":              None,
    "field_overrides":      None,
    "if_sid_overrides":     None,
    "if_group_overrides":   None,
    "level_informational":  5,
    "level_low":            7,
    "level_medium":         10,
    "level_high":           12,
    "level_critical":       15,
}


def _load_config_file(path: Path) -> Dict[str, Any]:
    """Load a YAML or JSON config file. Returns {} on empty/error."""
    from ruamel.yaml import YAML as _YAML
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        _y = _YAML(typ="safe")
        try:
            return _y.load(content) or {}
        except Exception as exc:
            console.print(f"[error]✕  Config file parse error: {exc}[/]")
            raise typer.Exit(1)
    elif path.suffix.lower() == ".json":
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            console.print(f"[error]✕  Config JSON error: {exc}[/]")
            raise typer.Exit(1)
    else:
        console.print(f"[error]✕  Unsupported config format '{path.suffix}' — use .yaml or .json[/]")
        raise typer.Exit(1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _banner() -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]Sig[/][bold white]Waz[/]  [dim]v{__version__}[/]\n"
        "[dim]Sigma → Wazuh  ·  State-of-the-art converter[/]",
        border_style="cyan",
        padding=(0, 4),
    ))
    console.print()


def _level_color(level: str) -> str:
    return {
        "informational": "dim white",
        "low": "green",
        "medium": "yellow",
        "high": "orange1",
        "critical": "bold red",
    }.get(level.lower(), "white")


def _status_icon(errors: list, skipped: list) -> str:
    if errors:
        return "[error]✕[/]"
    if skipped:
        return "[warning]⚠[/]"
    return "[success]✓[/]"


def _parse_csv(value: str) -> List[str]:
    """Split a comma-separated string into a stripped, non-empty list."""
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def _load_json_opt(value: Optional[str], flag: str) -> dict:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        console.print(f"[warning]⚠  {flag} is not valid JSON — ignoring.[/]")
        return {}


# ── Build config ──────────────────────────────────────────────────────────────

def _build_config(
    rule_id_start: Optional[int],
    no_full_log: Optional[bool],
    email_alert: Optional[bool],
    email_levels: Optional[str],
    process_experimental: Optional[bool],
    excluded_statuses: Optional[str],
    min_level: Optional[str],
    allowed_products: Optional[str],
    sigma_guid_email: Optional[str],
    rules_link_base: Optional[str],
    split_size: Optional[int],
    id_file: Optional[str],
    field_overrides: Optional[str],
    if_sid_overrides: Optional[str],
    if_group_overrides: Optional[str],
    level_informational: Optional[int],
    level_low: Optional[int],
    level_medium: Optional[int],
    level_high: Optional[int],
    level_critical: Optional[int],
    config_data: Optional[Dict[str, Any]] = None,
) -> ConversionConfig:

    def _r(cli_val: Any, cfg_key: str) -> Any:
        """CLI wins if explicitly set (not None), else config file, else hardcoded default."""
        if cli_val is not None:
            return cli_val
        cfg = config_data or {}
        if cfg_key in cfg and cfg[cfg_key] is not None:
            return cfg[cfg_key]
        return _DEFAULTS[cfg_key]

    def _rl(cli_csv: Optional[str], cfg_key: str) -> List[str]:
        """Resolve a list: CSV string from CLI, list from config, or empty default."""
        if cli_csv is not None:
            return _parse_csv(cli_csv)
        cfg = config_data or {}
        if cfg_key in cfg and cfg[cfg_key] is not None:
            v = cfg[cfg_key]
            if isinstance(v, list):
                return [str(x).strip() for x in v if x]
            return _parse_csv(str(v))
        return _parse_csv(_DEFAULTS.get(cfg_key, "") or "")

    def _ro(cli_json: Optional[str], cfg_key: str, flag: str) -> dict:
        if cli_json is not None:
            return _load_json_opt(cli_json, flag)
        cfg = config_data or {}
        v = cfg.get(cfg_key)
        if isinstance(v, dict):
            return v
        if v:
            return _load_json_opt(str(v), flag)
        return {}

    r_process_experimental = _r(process_experimental, "process_experimental")
    es = _rl(excluded_statuses, "excluded_statuses")
    # legacy --no-experimental maps to excluding "experimental"
    if not r_process_experimental and "experimental" not in es:
        es.append("experimental")

    r_min_level = _r(min_level, "min_level")
    r_sigma_guid_email = _rl(sigma_guid_email, "sigma_guid_email")

    tracker_path = _r(id_file, "id_file")
    tracker = IDTracker(tracker_path) if tracker_path else None

    return ConversionConfig(
        rule_id_start=_r(rule_id_start, "rule_id_start"),
        levels={
            "informational": _r(level_informational, "level_informational"),
            "low":           _r(level_low, "level_low"),
            "medium":        _r(level_medium, "level_medium"),
            "high":          _r(level_high, "level_high"),
            "critical":      _r(level_critical, "level_critical"),
        },
        no_full_log=_r(no_full_log, "no_full_log"),
        email_alert=_r(email_alert, "email_alert"),
        email_levels=_rl(email_levels, "email_levels"),
        sigma_guid_email=r_sigma_guid_email,
        process_experimental=r_process_experimental,
        excluded_statuses=es,
        min_level=r_min_level.strip().lower() if r_min_level else "",
        allowed_products=_rl(allowed_products, "allowed_products"),
        rules_link_base=_r(rules_link_base, "rules_link_base"),
        split_size=_r(split_size, "split_size"),
        field_map_overrides=_ro(field_overrides, "field_overrides", "--field-overrides"),
        if_sid_overrides=_ro(if_sid_overrides, "if_sid_overrides", "--if-sid-overrides"),
        if_group_overrides=_ro(if_group_overrides, "if_group_overrides", "--if-group-overrides"),
        id_tracker=tracker,
    )


# ── Shared option definitions ─────────────────────────────────────────────────

_OPT_RULE_ID     = typer.Option(None, "--rule-id-start", "-r",
    help="Starting Wazuh rule ID. IDs are allocated sequentially from this base. "
         "Example: -r 910000 → IDs 910001, 910002, …")

_OPT_NO_FULL_LOG = typer.Option(None, "--no-full-log/--full-log",
    help="Append <options>no_full_log</options> to each rule. "
         "Prevents Wazuh from logging the full event payload — strongly recommended for performance.")

_OPT_EMAIL       = typer.Option(None, "--email-alert/--no-email",
    help="Append <options>alert_by_email</options> to qualifying rules. "
         "Combine with --email-levels to target specific severities.")

_OPT_EMAIL_LVL   = typer.Option(None, "--email-levels", "-E",
    help="Comma-separated Sigma levels that trigger email alerts when --email-alert is set. "
         "Example: --email-levels critical,high")

_OPT_EXPERIMENTAL = typer.Option(None, "--experimental/--no-experimental",
    help="[Deprecated — prefer --excluded-statuses] "
         "Whether to convert rules whose Sigma status is 'experimental'.")

_OPT_EXCLUDED    = typer.Option(None, "--excluded-statuses", "-x",
    help="Comma-separated Sigma statuses to skip. Rules with a matching status are counted "
         "as skipped (not errors). "
         "Default: experimental,test,deprecated,unsupported (only stable rules are converted). "
         "Choices: experimental, test, stable, deprecated, unsupported. "
         "Example: -x experimental,deprecated  or  -x '' to convert all statuses")

_OPT_MIN_LEVEL   = typer.Option(None, "--min-level", "-l",
    help="Skip rules whose Sigma severity is below this threshold. "
         "Choices: low, medium, high, critical (empty = convert all). "
         "Example: --min-level medium  → skips informational and low")

_OPT_PRODUCTS    = typer.Option(None, "--allowed-products", "-p",
    help="Comma-separated logsource product whitelist. Rules for any other product are skipped. "
         "Empty = convert all products. "
         "Example: --allowed-products windows,linux,aws")

_OPT_GUID_EMAIL  = typer.Option(None, "--sigma-guid-email",
    help="Comma-separated Sigma rule UUIDs that always trigger email alerts, regardless of level. "
         "Example: --sigma-guid-email 6f3e2987-db24-4c46-a4c5-8b8b4b7f8e21")

_OPT_LINK_BASE   = typer.Option(
    None,
    "--rules-link",
    help="Base URL prepended to rule references in <info type='link'> elements. "
         "Set to your internal mirror if needed.")

_OPT_SPLIT       = typer.Option(None, "--split", "-s",
    help="Maximum number of rules per output XML file (0 = no split). "
         "Splitting prevents Wazuh OOM on import for large rulesets. "
         "Example: --split 100 → outputs rules-1.xml, rules-2.xml, …")

_OPT_ID_FILE     = typer.Option(None, "--id-file", "-i",
    help="Path to a JSON file for persisting Sigma GUID → Wazuh rule ID mappings. "
         "Guarantees stable IDs across re-runs of the same ruleset. "
         "Example: --id-file ~/.sigwaz/ids.json")

_OPT_FO          = typer.Option(None, "--field-overrides",
    help='JSON string overriding per-product field mappings. '
         'Format: \'{"product": {"SigmaField": "wazuh.decoder.path"}}\' '
         'Example: --field-overrides \'{"windows": {"CommandLine": "win.eventdata.cmdline"}}\'')

_OPT_IFSO        = typer.Option(None, "--if-sid-overrides",
    help='JSON string overriding per-product parent rule IDs (if_sid). '
         'Format: \'{"product": "sid1, sid2"}\' '
         'Example: --if-sid-overrides \'{"sysmon": "184665, 185000"}\'')

_OPT_IFGO        = typer.Option(None, "--if-group-overrides",
    help='JSON string overriding per-product parent rule groups (if_group). '
         'Format: \'{"product": "group_name"}\' '
         'Example: --if-group-overrides \'{"apache": "web_log"}\'')

_OPT_LVL_INFO    = typer.Option(None, "--level-informational",
    help="Wazuh rule level (0-15) for Sigma 'informational' rules. Default: 5")
_OPT_LVL_LOW     = typer.Option(None, "--level-low",
    help="Wazuh rule level (0-15) for Sigma 'low' rules. Default: 7")
_OPT_LVL_MEDIUM  = typer.Option(None, "--level-medium",
    help="Wazuh rule level (0-15) for Sigma 'medium' rules. Default: 10")
_OPT_LVL_HIGH    = typer.Option(None, "--level-high",
    help="Wazuh rule level (0-15) for Sigma 'high' rules. Default: 12")
_OPT_LVL_CRIT    = typer.Option(None, "--level-critical",
    help="Wazuh rule level (0-15) for Sigma 'critical' rules. Default: 15")


# ── convert ───────────────────────────────────────────────────────────────────

@app.command(
    "convert",
    help=(
        "Convert a [bold]single[/bold] Sigma YAML rule to Wazuh XML.\n\n"
        "Multi-document YAML files (multiple rules separated by ---) are also supported.\n\n"
        "[dim]Examples:[/dim]\n"
        "  sigwaz convert rule.yml\n"
        "  sigwaz convert rule.yml -o rule_rules.xml\n"
        "  sigwaz convert rule.yml -r 910000 --no-full-log --level-high 14\n"
        "  sigwaz convert rule.yml --excluded-statuses experimental --min-level medium"
    ),
)
def cmd_convert(
    input_file: Path = typer.Argument(..., help="Path to Sigma .yml / .yaml rule file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o",
        help="Output XML file path. If omitted, XML is printed to stdout. "
             "The _rules.xml suffix convention is recommended: rule_rules.xml"),
    dry_run: bool = typer.Option(False, "--dry-run", "-d",
        help="Parse and analyse the rule without writing any output files."),
    show_xml: bool = typer.Option(False, "--show-xml", "-X",
        help="Print XML to the terminal even when --output is set."),
    validate: bool = typer.Option(True, "--validate/--no-validate",
        help="Run Wazuh XML validation after conversion (structure, duplicate IDs, etc.)."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c",
        help="Path to a YAML or JSON config file. "
             "All conversion parameters can be set in the file; explicit CLI flags override them. "
             "Example: --config ~/.sigwaz/config.yaml"),
    rule_id_start: Optional[int]  = _OPT_RULE_ID,
    no_full_log:   Optional[bool] = _OPT_NO_FULL_LOG,
    email_alert:   Optional[bool] = _OPT_EMAIL,
    email_levels:  Optional[str]  = _OPT_EMAIL_LVL,
    process_experimental: Optional[bool] = _OPT_EXPERIMENTAL,
    excluded_statuses: Optional[str] = _OPT_EXCLUDED,
    min_level:     Optional[str]  = _OPT_MIN_LEVEL,
    allowed_products: Optional[str] = _OPT_PRODUCTS,
    sigma_guid_email: Optional[str] = _OPT_GUID_EMAIL,
    rules_link_base: Optional[str] = _OPT_LINK_BASE,
    split_size:    Optional[int]  = _OPT_SPLIT,
    id_file: Optional[str] = _OPT_ID_FILE,
    field_overrides: Optional[str] = _OPT_FO,
    if_sid_overrides: Optional[str] = _OPT_IFSO,
    if_group_overrides: Optional[str] = _OPT_IFGO,
    level_informational: Optional[int] = _OPT_LVL_INFO,
    level_low:           Optional[int] = _OPT_LVL_LOW,
    level_medium:        Optional[int] = _OPT_LVL_MEDIUM,
    level_high:          Optional[int] = _OPT_LVL_HIGH,
    level_critical:      Optional[int] = _OPT_LVL_CRIT,
) -> None:
    _banner()

    if not input_file.exists():
        console.print(f"[error]✕  File not found: {input_file}[/]")
        raise typer.Exit(1)

    _MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB
    if input_file.stat().st_size > _MAX_FILE_BYTES:
        console.print(f"[error]✕  File too large ({input_file.stat().st_size / 1_048_576:.1f} MB). Maximum: 50 MB.[/]")
        raise typer.Exit(1)

    cfg_data = _load_config_file(config_file) if config_file else {}
    config = _build_config(
        rule_id_start, no_full_log, email_alert, email_levels,
        process_experimental, excluded_statuses, min_level, allowed_products,
        sigma_guid_email, rules_link_base, split_size, id_file,
        field_overrides, if_sid_overrides, if_group_overrides,
        level_informational, level_low, level_medium, level_high, level_critical,
        config_data=cfg_data,
    )

    yaml_str = input_file.read_text(encoding="utf-8")

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) as prog:
        task = prog.add_task("Converting rule…", total=None)
        t0 = time.perf_counter()
        result = convert_single(yaml_str, config)
        elapsed = time.perf_counter() - t0
        prog.update(task, completed=True)

    # Summary panel
    lc   = _level_color(result.sigma_level)
    icon = _status_icon(result.errors, result.skipped)
    lines = [
        f"  {icon}  [bold]{escape(result.sigma_title)}[/]",
        f"  [muted]Sigma ID :[/] [dim]{result.sigma_id or '—'}[/]",
        f"  [muted]Level    :[/] [{lc}]{result.sigma_level}[/]",
        f"  [muted]Status   :[/] {result.sigma_status or '—'}",
        f"  [muted]Wazuh IDs:[/] [rule_id]{', '.join(str(i) for i in result.rule_ids) or '—'}[/]",
        f"  [muted]Rules    :[/] [accent]{result.rule_count}[/] generated  "
        f"[muted]({elapsed * 1000:.1f} ms)[/]",
    ]
    if result.mitre_techniques:
        lines.append(f"  [muted]MITRE    :[/] [mitre]{', '.join(result.mitre_techniques)}[/]")
    for s in result.skipped:
        detail = f" — {s.detail}" if s.detail else ""
        lines.append(f"  [warning]⚠  Skipped:[/] {s.reason}{detail}")
    for e in result.errors:
        lines.append(f"  [error]✕  Error  :[/] {e}")
    for w in result.warnings:
        lines.append(f"  [warning]⚠  Warning:[/] {w}")

    console.print(Panel(
        "\n".join(lines),
        title="[bold cyan]Conversion Result[/]",
        border_style="cyan",
        padding=(0, 1),
    ))

    # Validation
    if validate and result.xml:
        vr = validate_xml(result.xml)
        if vr.valid:
            console.print(f"  [success]✓[/] XML validation passed  ({vr.rule_count} rule(s))")
        else:
            console.print(f"  [error]✕  XML validation failed:[/]")
            for e in vr.errors:
                console.print(f"      [error]{e}[/]")
        for w in vr.warnings:
            console.print(f"      [warning]⚠  {w}[/]")
        console.print()

    # Output
    if result.xml and not dry_run:
        if output:
            chunks = split_xml(result.xml, config.split_size) if config.split_size > 0 else [result.xml]
            if len(chunks) > 1:
                for i, chunk in enumerate(chunks):
                    fname = output.parent / filename_for_chunk(output.stem, i, len(chunks))
                    fname.write_text(chunk, encoding="utf-8")
                    console.print(f"  [success]↓[/] Saved [accent]{fname}[/]  ({len(chunk):,} bytes)")
            else:
                output.write_text(result.xml, encoding="utf-8")
                console.print(f"  [success]↓[/] Saved [accent]{output}[/]  ({len(result.xml):,} bytes)")
        if not output or show_xml:
            console.print(Rule("[dim]XML Output[/]", style="dim cyan"))
            console.print(Syntax(result.xml, "xml", theme="monokai", line_numbers=True))
    elif dry_run:
        console.print("  [muted]Dry-run — no files written.[/]")

    console.print()


# ── batch ─────────────────────────────────────────────────────────────────────

@app.command(
    "batch",
    help=(
        "Batch-convert [bold]multiple[/bold] Sigma rules from a directory, multi-doc YAML, or ZIP.\n\n"
        "When given a directory, all .yml/.yaml files are collected recursively "
        "(skipping any path component named 'deprecated').\n\n"
        "[dim]Examples:[/dim]\n"
        "  sigwaz batch rules/windows/ -o output/\n"
        "  sigwaz batch rules.yml -o output/ --split 50\n"
        "  sigwaz batch rules.zip -o output/ --split 50\n"
        "  sigwaz batch rules/ -o output/ --config ~/.sigwaz/config.yaml\n"
        "  sigwaz batch rules/ -o output/ --min-level medium "
        "--excluded-statuses experimental,deprecated\n"
        "  sigwaz batch rules/ -o output/ --allowed-products windows,linux --zip"
    ),
)
def cmd_batch(
    input_path: Path = typer.Argument(...,
        help="Directory of .yml files, a single multi-document YAML file, or a ZIP archive containing .yml/.yaml files"),
    output_dir: Path = typer.Option(Path("."), "--output", "-o",
        help="Directory where output XML files are written. Created if it does not exist."),
    stem: Optional[str] = typer.Option(None, "--name", "-n",
        help="Base stem for output filenames. Defaults to the input directory/file name. "
             "Output files: <stem>_rules.xml or <stem>_rules-1.xml, <stem>_rules-2.xml, …"),
    zip_output: bool = typer.Option(False, "--zip", "-z",
        help="Bundle all output XML files into a single ZIP archive alongside the XML files."),
    dry_run: bool = typer.Option(False, "--dry-run", "-d",
        help="Convert and report statistics without writing any output files."),
    validate: bool = typer.Option(True, "--validate/--no-validate",
        help="Run Wazuh XML validation on the merged output after conversion."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c",
        help="Path to a YAML or JSON config file. "
             "All conversion parameters can be set in the file; explicit CLI flags override them. "
             "Example: --config ~/.sigwaz/config.yaml"),
    rule_id_start: Optional[int]  = _OPT_RULE_ID,
    no_full_log:   Optional[bool] = _OPT_NO_FULL_LOG,
    email_alert:   Optional[bool] = _OPT_EMAIL,
    email_levels:  Optional[str]  = _OPT_EMAIL_LVL,
    process_experimental: Optional[bool] = _OPT_EXPERIMENTAL,
    excluded_statuses: Optional[str] = _OPT_EXCLUDED,
    min_level:     Optional[str]  = _OPT_MIN_LEVEL,
    allowed_products: Optional[str] = _OPT_PRODUCTS,
    sigma_guid_email: Optional[str] = _OPT_GUID_EMAIL,
    rules_link_base: Optional[str] = _OPT_LINK_BASE,
    split_size:    Optional[int]  = _OPT_SPLIT,
    id_file: Optional[str] = _OPT_ID_FILE,
    field_overrides: Optional[str] = _OPT_FO,
    if_sid_overrides: Optional[str] = _OPT_IFSO,
    if_group_overrides: Optional[str] = _OPT_IFGO,
    level_informational: Optional[int] = _OPT_LVL_INFO,
    level_low:           Optional[int] = _OPT_LVL_LOW,
    level_medium:        Optional[int] = _OPT_LVL_MEDIUM,
    level_high:          Optional[int] = _OPT_LVL_HIGH,
    level_critical:      Optional[int] = _OPT_LVL_CRIT,
) -> None:
    _banner()

    cfg_data = _load_config_file(config_file) if config_file else {}
    config = _build_config(
        rule_id_start, no_full_log, email_alert, email_levels,
        process_experimental, excluded_statuses, min_level, allowed_products,
        sigma_guid_email, rules_link_base, split_size, id_file,
        field_overrides, if_sid_overrides, if_group_overrides,
        level_informational, level_low, level_medium, level_high, level_critical,
        config_data=cfg_data,
    )

    # Collect YAML
    yaml_docs: List[str] = []

    if input_path.is_dir():
        yml_files = sorted(input_path.rglob("*.yml")) + sorted(input_path.rglob("*.yaml"))
        yml_files = [f for f in yml_files if "deprecated" not in f.parts]
        for f in yml_files:
            yaml_docs.append(f.read_text(encoding="utf-8"))
        out_stem = stem or input_path.name
    elif input_path.is_file() and input_path.suffix.lower() == ".zip":
        _MAX_ZIP_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB
        _MAX_ZIP_FILES = 5_000
        total_uncompressed = 0
        try:
            with zipfile.ZipFile(input_path, "r") as zf:
                members = [
                    m for m in zf.infolist()
                    if m.filename.lower().endswith((".yml", ".yaml"))
                    and not m.filename.startswith("/")
                    and ".." not in m.filename
                ]
                if len(members) > _MAX_ZIP_FILES:
                    console.print(f"[error]✕  ZIP contains {len(members):,} YAML files — limit is {_MAX_ZIP_FILES:,}[/]")
                    raise typer.Exit(1)
                for member in members:
                    total_uncompressed += member.file_size
                    if total_uncompressed > _MAX_ZIP_UNCOMPRESSED:
                        console.print("[error]✕  ZIP uncompressed content exceeds 200 MB — possible zip bomb[/]")
                        raise typer.Exit(1)
                    content = zf.read(member.filename).decode("utf-8", errors="replace")
                    yaml_docs.append(content)
        except zipfile.BadZipFile:
            console.print(f"[error]✕  Invalid or corrupt ZIP file: {input_path}[/]")
            raise typer.Exit(1)
        out_stem = stem or input_path.stem
    elif input_path.is_file():
        import re as _re
        raw = input_path.read_text(encoding="utf-8")
        docs = _re.split(r"^---\s*$", raw, flags=_re.MULTILINE)
        yaml_docs = [d.strip() for d in docs if d.strip()]
        out_stem = stem or input_path.stem
    else:
        console.print(f"[error]✕  Path not found: {input_path}[/]")
        raise typer.Exit(1)

    if not yaml_docs:
        console.print("[warning]⚠  No YAML rules found.[/]")
        raise typer.Exit(0)

    console.print(f"  Found [accent]{len(yaml_docs)}[/] Sigma rule(s) — converting…\n")

    # Active filters summary
    active_filters: List[str] = []
    if config.excluded_statuses:
        active_filters.append(f"exclude-status={','.join(config.excluded_statuses)}")
    if config.min_level:
        active_filters.append(f"min-level={config.min_level}")
    if config.allowed_products:
        active_filters.append(f"products={','.join(config.allowed_products)}")
    if active_filters:
        console.print(f"  [muted]Filters  :[/] {' · '.join(active_filters)}\n")

    # Convert
    all_results = []
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=35, style="cyan", complete_style="bold cyan"),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("Converting", total=len(yaml_docs))
        for yaml_str in yaml_docs:
            all_results.append(convert_single(yaml_str, config))
            prog.advance(task)

    ok          = sum(1 for r in all_results if r.rule_count > 0 and not r.errors)
    warn        = sum(1 for r in all_results if r.skipped)
    err         = sum(1 for r in all_results if r.errors)
    skipped_tot = sum(len(r.skipped) for r in all_results)
    total_rules = sum(r.rule_count for r in all_results)

    # Results table
    table = Table(
        box=box.ROUNDED, border_style="cyan",
        show_header=True, header_style="bold cyan",
    )
    table.add_column("Title",  style="white", no_wrap=False, max_width=44)
    table.add_column("Level",  justify="center", width=14)
    table.add_column("IDs",    style="magenta", width=18)
    table.add_column("MITRE",  style="yellow", width=20)
    table.add_column("Status", justify="center", width=8)

    for r in all_results:
        lc       = _level_color(r.sigma_level)
        icon     = _status_icon(r.errors, r.skipped)
        ids_str  = ", ".join(str(i) for i in r.rule_ids[:3])
        if len(r.rule_ids) > 3:
            ids_str += f" +{len(r.rule_ids) - 3}"
        mit_str  = ", ".join(r.mitre_techniques[:2])
        if len(r.mitre_techniques) > 2:
            mit_str += f" +{len(r.mitre_techniques) - 2}"
        table.add_row(
            escape(r.sigma_title or "—"),
            f"[{lc}]{r.sigma_level}[/]",
            ids_str or "—",
            mit_str or "—",
            icon,
        )

    console.print(table)
    console.print()
    console.print(
        f"  [success]✓ {ok}[/] converted  "
        f"[warning]⚠ {skipped_tot}[/] skipped  "
        f"[error]✕ {err}[/] errors  "
        f"[accent]{total_rules}[/] Wazuh rules total"
    )
    console.print()

    # Output
    merged = merge_results_xml(all_results)
    base_stem = f"{out_stem}_rules"

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

        written_files: List[Path] = []
        if config.split_size > 0 and merged:
            chunks = split_xml(merged, config.split_size)
            for i, chunk in enumerate(chunks):
                fname = output_dir / filename_for_chunk(base_stem, i, len(chunks))
                fname.write_text(chunk, encoding="utf-8")
                written_files.append(fname)
                n_rules = chunk.count("<rule ")
                console.print(
                    f"  [success]↓[/] [accent]{fname.name}[/]"
                    f"  ({n_rules} rules · {len(chunk) / 1024:.1f} KB)"
                )
        elif merged:
            out_file = output_dir / f"{base_stem}.xml"
            out_file.write_text(merged, encoding="utf-8")
            written_files = [out_file]
            console.print(
                f"  [success]↓[/] [accent]{out_file.name}[/]"
                f"  ({total_rules} rules · {len(merged) / 1024:.1f} KB)"
            )

        if zip_output and written_files:
            zip_path = output_dir / f"{base_stem}.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in written_files:
                    zf.write(f, f.name)
            console.print(
                f"  [success]↓[/] [accent]{zip_path.name}[/]"
                f"  (ZIP · {zip_path.stat().st_size / 1024:.1f} KB)"
            )
    else:
        console.print("  [muted]Dry-run — no files written.[/]")

    # Validation
    if validate and merged:
        vr = validate_xml(merged)
        if vr.valid:
            console.print(
                f"\n  [success]✓[/] XML validation passed"
                f"  ({vr.rule_count} rule(s), {len(vr.warnings)} warning(s))"
            )
        else:
            console.print(f"\n  [error]✕  XML validation failed:[/]")
            for e in vr.errors[:5]:
                console.print(f"      [error]{e}[/]")
        for w in vr.warnings[:3]:
            console.print(f"      [warning]⚠  {w}[/]")

    console.print()


# ── check ─────────────────────────────────────────────────────────────────────

@app.command(
    "check",
    help=(
        "Validate an existing Wazuh XML rules file.\n\n"
        "Checks: XML well-formedness, root element, rule ID uniqueness, "
        "level range (0-15), presence of <description>, rules with no <field> "
        "(may be too broad).\n\n"
        "[dim]Examples:[/dim]\n"
        "  sigwaz check output/windows_rules.xml\n"
        "  sigwaz check /var/ossec/etc/rules/sigma_rules.xml"
    ),
)
def cmd_check(
    input_file: Path = typer.Argument(..., help="Path to Wazuh XML rules file to validate"),
) -> None:
    _banner()

    if not input_file.exists():
        console.print(f"[error]✕  File not found: {input_file}[/]")
        raise typer.Exit(1)

    xml_str = input_file.read_text(encoding="utf-8")

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]Validating…"),
        TimeElapsedColumn(),
        console=console, transient=True,
    ) as prog:
        prog.add_task("", total=None)
        vr = validate_xml(xml_str)

    if vr.valid:
        console.print(
            f"  [success]✓[/] Valid Wazuh XML — "
            f"[accent]{vr.rule_count}[/] rule(s) · "
            f"{len(vr.warnings)} warning(s)"
        )
    else:
        console.print(f"  [error]✕  Validation failed ({len(vr.errors)} error(s))[/]")
        for e in vr.errors:
            console.print(f"      [error]{e}[/]")

    for w in vr.warnings:
        console.print(f"      [warning]⚠  {w}[/]")

    if vr.duplicate_ids:
        dup_preview = ", ".join(str(i) for i in list(vr.duplicate_ids)[:8])
        console.print(f"      [warning]⚠  Duplicate IDs: {dup_preview}[/]")

    console.print()
    raise typer.Exit(0 if vr.valid else 1)


# ── info ──────────────────────────────────────────────────────────────────────

@app.command(
    "info",
    help=(
        "Show SigWaz version, supported products, and field mapping statistics.\n\n"
        "[dim]Examples:[/dim]\n"
        "  sigwaz info\n"
        "  sigwaz info | head -40"
    ),
)
def cmd_info() -> None:
    _banner()

    products = sorted(list_products())
    total_fields = sum(len(v) for v in FIELD_MAPS.values())

    console.print(Panel(
        f"  [muted]Version   :[/] [accent]v{__version__}[/]\n"
        f"  [muted]Engine    :[/] Sigma → Wazuh PCRE2 converter\n"
        f"  [muted]Products  :[/] [accent]{len(products)}[/] supported log sources\n"
        f"  [muted]Field maps:[/] [accent]{total_fields}[/] total Sigma → Wazuh field mappings\n"
        f"  [muted]SID maps  :[/] [accent]{len(IF_SID_MAP)}[/] if_sid entries across all products",
        title="[bold cyan]SigWaz Info[/]",
        border_style="cyan",
        padding=(0, 1),
    ))

    table = Table(
        title="[bold cyan]Supported Products[/]",
        box=box.ROUNDED, border_style="cyan",
        show_header=True, header_style="bold cyan",
    )
    table.add_column("Product",       style="yellow", width=26)
    table.add_column("Field Maps",    justify="right", width=12)
    table.add_column("if_sid",        justify="center", width=8)
    table.add_column("if_group",      justify="center", width=10)

    for p in products:
        fmap_count = len(FIELD_MAPS.get(p, {}))
        has_sid    = "[success]✓[/]" if p in IF_SID_MAP   else "[muted]—[/]"
        has_group  = "[success]✓[/]" if p in IF_GROUP_MAP  else "[muted]—[/]"
        table.add_row(p, str(fmap_count), has_sid, has_group)

    console.print(table)
    console.print()


# ── fieldmaps ─────────────────────────────────────────────────────────────────

@app.command(
    "fieldmaps",
    help=(
        "Display Sigma → Wazuh field mapping tables.\n\n"
        "[dim]Examples:[/dim]\n"
        "  sigwaz fieldmaps\n"
        "  sigwaz fieldmaps windows\n"
        "  sigwaz fieldmaps sysmon --json"
    ),
)
def cmd_fieldmaps(
    product: Optional[str] = typer.Argument(None,
        help="Filter by product name (optional). Run 'sigwaz info' for available products."),
    json_output: bool = typer.Option(False, "--json",
        help="Output raw JSON instead of formatted tables."),
) -> None:
    _banner()
    if product:
        p = product.lower()
        if p not in FIELD_MAPS:
            console.print(f"[error]✕  Unknown product: {product}[/]")
            console.print(f"  Available: {', '.join(sorted(list_products()))}")
            raise typer.Exit(1)
        data = {p: FIELD_MAPS[p]}
    else:
        data = FIELD_MAPS

    if json_output:
        console.print_json(json.dumps(data, indent=2))
        return

    for prod, fmap in data.items():
        table = Table(
            title=f"[bold cyan]{prod}[/]  [dim]({len(fmap)} fields)[/]",
            box=box.SIMPLE_HEAD, border_style="dim cyan",
            show_header=True, header_style="bold cyan",
        )
        table.add_column("Sigma Field", style="yellow")
        table.add_column("Wazuh Decoder Path", style="green")
        for sigma_f, wazuh_p in fmap.items():
            table.add_row(sigma_f, wazuh_p)
        console.print(table)
        console.print()


# ── sidmaps ───────────────────────────────────────────────────────────────────

@app.command(
    "sidmaps",
    help=(
        "Display parent rule ID (if_sid) and group (if_group) mappings per product.\n\n"
        "[dim]Examples:[/dim]\n"
        "  sigwaz sidmaps\n"
        "  sigwaz sidmaps --json"
    ),
)
def cmd_sidmaps(
    json_output: bool = typer.Option(False, "--json",
        help="Output raw JSON instead of a formatted table."),
) -> None:
    _banner()
    if json_output:
        console.print_json(json.dumps(IF_SID_MAP, indent=2))
        return

    table = Table(
        title="[bold cyan]Parent Rule ID Mappings (if_sid)[/]",
        box=box.ROUNDED, border_style="cyan",
        header_style="bold cyan",
    )
    table.add_column("Product / Service", style="yellow", width=28)
    table.add_column("if_sid values", style="white")
    for prod, sids in IF_SID_MAP.items():
        table.add_row(prod, sids)
    console.print(table)
    console.print()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
