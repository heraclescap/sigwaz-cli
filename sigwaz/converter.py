"""
SigWaz Core Conversion Engine — 100% parametrizable.
Entry points:
  convert_single(yaml_str, config) → ConversionResult
  convert_batch(yaml_str, config)  → List[ConversionResult]
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import xml.dom.minidom as minidom

from .sigma_parser import SigmaRule, parse_rule, parse_multi
from .sid_maps import resolve_product
from .wazuh_builder import build_rule_element
from .mitre import extract_mitre_ids, extract_tactics
from .utils.id_tracker import IDTracker


# ── Default level map ────────────────────────────────────────────────────────

DEFAULT_LEVELS: Dict[str, int] = {
    "informational": 5,
    "low": 7,
    "medium": 10,
    "high": 12,
    "critical": 15,
}


# ── Configuration ────────────────────────────────────────────────────────────

_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]


def _level_index(level: str) -> int:
    try:
        return _LEVEL_ORDER.index(level.lower())
    except ValueError:
        return 0


@dataclass
class ConversionConfig:
    rule_id_start: int = 900000
    levels: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_LEVELS))
    no_full_log: bool = True
    email_alert: bool = False
    email_levels: List[str] = field(default_factory=lambda: ["critical", "high"])
    sigma_guid_email: List[str] = field(default_factory=list)
    # per-product {sigma_field: wazuh_path} overrides
    field_map_overrides: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # per-product if_sid override strings
    if_sid_overrides: Dict[str, str] = field(default_factory=dict)
    # per-product if_group override strings
    if_group_overrides: Dict[str, str] = field(default_factory=dict)
    rules_link_base: str = "https://github.com/SigmaHQ/sigma/tree/master/rules"
    split_size: int = 0          # 0 = no split; N = max rules per XML file
    process_experimental: bool = True  # legacy; prefer excluded_statuses
    # ── New filters ──────────────────────────────────────────────────────────
    excluded_statuses: List[str] = field(default_factory=lambda: ["experimental", "test", "deprecated", "unsupported"])
    min_level: str = ""          # skip rules below this level (empty = all)
    allowed_products: List[str] = field(default_factory=list)    # empty = all products
    id_tracker: Optional[IDTracker] = field(default=None, repr=False)

    def get_level(self, sigma_level: str) -> int:
        return self.levels.get(sigma_level.lower(), self.levels.get("medium", 10))


# ── Result types ─────────────────────────────────────────────────────────────

@dataclass
class SkipInfo:
    reason: str
    detail: str = ""


@dataclass
class ConversionResult:
    xml: str = ""                       # primary XML output (first file if split)
    xml_files: List[str] = field(default_factory=list)  # all files if split > 1
    rule_count: int = 0
    rule_ids: List[int] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    skipped: List[SkipInfo] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sigma_id: str = ""
    sigma_title: str = ""
    sigma_level: str = ""
    sigma_status: str = ""


# ── Skip checks ──────────────────────────────────────────────────────────────

def _should_skip(rule: SigmaRule, condition: str, config: ConversionConfig) -> Optional[SkipInfo]:
    if rule.errors:
        return SkipInfo("parse_error", "; ".join(rule.errors))

    # ── Status filter ────────────────────────────────────────────────────────
    rule_status = (rule.status or "").lower()
    excluded = [s.lower() for s in config.excluded_statuses]
    # Legacy flag: process_experimental=False is equivalent to excluding "experimental"
    if not config.process_experimental and "experimental" not in excluded:
        excluded.append("experimental")
    if rule_status and rule_status in excluded:
        return SkipInfo("status_excluded", f"Status '{rule.status}' is excluded")

    # ── Minimum severity level ───────────────────────────────────────────────
    if config.min_level:
        if _level_index(rule.level) < _level_index(config.min_level):
            return SkipInfo("level_filtered", f"Level '{rule.level}' is below minimum '{config.min_level}'")

    # ── Allowed products ─────────────────────────────────────────────────────
    if config.allowed_products:
        rule_product = rule.logsource.get("product", "").lower()
        if rule_product and rule_product not in [p.lower() for p in config.allowed_products]:
            return SkipInfo("product_filtered", f"Product '{rule_product}' not in allowed list")

    # ── Unsupported constructs ───────────────────────────────────────────────
    det_str = str(rule.detection)
    if "timeframe" in det_str:
        return SkipInfo("timeframe", "Timeframe conditions are not supported")

    # Only check detection keys for CIDR modifier (not values, which can mention "cidr" legitimately)
    det_keys = " ".join(str(k) for k in rule.detection.keys() if k != "condition").lower()
    if "|cidr" in det_keys:
        return SkipInfo("cidr", "CIDR conditions are not supported")

    if ("|" in condition
            and "1_of" not in condition and "all_of" not in condition
            and "1 of" not in condition and "all of" not in condition):
        return SkipInfo("near", "NEAR/pipe conditions are not supported")

    return None


# ── Condition tokenizer ───────────────────────────────────────────────────────

def _tokenize(condition: str) -> List[str]:
    return [t for t in condition.strip().split() if t]


def _expand_wildcards(tokens: List[str], detection_keys: List[str]) -> List[str]:
    """Expand 1_of / all_of wildcards. Handles both underscore ('1_of') and space ('1 of') forms."""
    result: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i].lower()

        # Detect qualifier — normalise "1 of" / "all of" (space form) to canonical token
        qualifier: str = ""
        if tok in ("1_of", "all_of"):
            qualifier = tok
        elif tok == "1" and i + 1 < len(tokens) and tokens[i + 1].lower() == "of":
            qualifier = "1_of"
            i += 1  # consume the "of" token
        elif tok == "all" and i + 1 < len(tokens) and tokens[i + 1].lower() == "of":
            qualifier = "all_of"
            i += 1  # consume the "of" token

        if qualifier:
            result.append(qualifier)
            i += 1
            if i < len(tokens):
                pattern = tokens[i]
                if pattern.endswith("*"):
                    prefix = pattern[:-1]
                    matches = [k for k in detection_keys if k.startswith(prefix) and k != "condition"]
                    sep = "or" if qualifier == "1_of" else "and"
                    for j, m in enumerate(matches):
                        result.append(m)
                        if j < len(matches) - 1:
                            result.append(sep)
                    i += 1
                    continue
                else:
                    result.append(pattern)
                    i += 1
                    continue
        else:
            result.append(tokens[i])
        i += 1
    return result


def _build_logic_paths(tokens: List[str], detection: Dict[str, Any]) -> List[List[str]]:
    """
    Split an AND/OR condition into OR-separated logic paths.
    Each path is a list of AND-chained detection names (prefixed with "not:" when negated).

    Special case: "not 1_of X*" — De Morgan: not(A or B) = (not A) and (not B).
    All OR-joined items stay in the same path, all negated.
    """
    det_keys = [k for k in detection if k != "condition"]
    tokens = _expand_wildcards(tokens, det_keys)

    paths: List[List[str]] = []
    current: List[str] = []
    negate = False
    not_1of_active = False  # True while inside a "not 1_of ..." expansion

    i = 0
    while i < len(tokens):
        tok = tokens[i].lower()

        if tok == "not":
            negate = True
            i += 1
            continue

        if tok == "or":
            if not_1of_active:
                # De Morgan: keep all items in current path (don't split)
                i += 1
                continue
            if current:
                paths.append(current)
            current = []
            negate = False
            i += 1
            continue

        if tok == "and":
            not_1of_active = False  # AND ends any active not_1of scope
            i += 1
            continue

        if tok in ("(", ")"):
            i += 1
            continue

        if tok == "1_of":
            if negate:
                not_1of_active = True
            i += 1
            continue

        if tok == "all_of":
            i += 1
            continue

        # It's a detection reference
        ref = tokens[i]  # preserve original case
        if ref in detection and ref != "condition":
            effective_negate = negate or not_1of_active
            entry = ("not:" + ref) if effective_negate else ref
            current.append(entry)
        negate = False
        i += 1

    if current:
        paths.append(current)

    return paths if paths else [[]]


# ── ID allocation ────────────────────────────────────────────────────────────

class _IDAllocator:
    def __init__(self, start: int, tracker: Optional[IDTracker]):
        self._next = start
        self._tracker = tracker
        self._used_this_run: set[int] = set()

    def allocate(self, sigma_guid: str) -> int:
        if self._tracker:
            existing = self._tracker.get_ids(sigma_guid)
            for wid in existing:
                if wid not in self._used_this_run:
                    self._used_this_run.add(wid)
                    return wid
        return self._fresh(sigma_guid)

    def _fresh(self, sigma_guid: str) -> int:
        while True:
            wid = self._next
            self._next += 1
            if self._tracker and self._tracker.is_used(wid):
                continue
            if wid in self._used_this_run:
                continue
            self._used_this_run.add(wid)
            if self._tracker:
                self._tracker.add_mapping(sigma_guid, wid)
            return wid

    def peek_next(self) -> int:
        return self._next

    def peek_range_end(self, count: int) -> int:
        return self._next + count - 1


# ── XML prettifier ────────────────────────────────────────────────────────────

def _prettify_rules(rules_els: List[Element]) -> str:
    root = Element("group")
    root.set("name", "sigma,")
    root.append(Comment("\n  Generated by SigWaz\n"))
    for el in rules_els:
        root.append(el)

    raw = tostring(root, encoding="unicode")
    dom = minidom.parseString(raw)
    pretty = dom.toprettyxml(indent="    ", encoding=None)

    # Remove the XML declaration added by minidom
    lines = pretty.split("\n")
    if lines[0].startswith("<?xml"):
        lines = lines[1:]
    result = "\n".join(lines)

    # Collapse single-line tags for readability
    for tag in ("id", "description", "options", "field", "info", "if_sid", "if_group"):
        result = re.sub(rf"<{tag}([^>]*)>\n\s+", f"<{tag}\\1>", result)
        result = re.sub(rf"\n\s+</{tag}>", f"</{tag}>", result)

    # Collapse inner <group> (no attributes — the logsource group element inside rules)
    # without touching the outer <group name="sigma,"> wrapper
    result = re.sub(r"<group>\n\s+", "<group>", result)
    result = re.sub(r"\n\s+</group>", "</group>", result)

    return result.strip()


# ── Single rule converter ─────────────────────────────────────────────────────

def convert_single(yaml_str: str, config: ConversionConfig) -> ConversionResult:
    """Convert a single Sigma YAML rule to Wazuh XML."""
    rule = parse_rule(yaml_str)
    result = ConversionResult(
        sigma_id=rule.id,
        sigma_title=rule.title,
        sigma_level=rule.level,
        sigma_status=rule.status,
        errors=list(rule.errors),
        warnings=list(rule.warnings),
    )

    if rule.errors:
        return result

    allocator = _IDAllocator(config.rule_id_start, config.id_tracker)
    rule_elements: List[Element] = []

    for condition_str in rule.conditions:
        tokens = _tokenize(condition_str)
        skip = _should_skip(rule, condition_str, config)
        if skip:
            result.skipped.append(skip)
            continue

        logic_paths = _build_logic_paths(tokens, rule.detection)
        product = resolve_product(rule.logsource)
        level_int = config.get_level(rule.level)

        for path in logic_paths:
            wid = allocator.allocate(rule.id or "unknown")
            el = build_rule_element(
                rule_id=wid,
                sigma_rule=rule,
                condition_tokens=path,
                detection=rule.detection,
                product=product,
                level_int=level_int,
                config=config,
            )
            if el is not None:
                rule_elements.append(el)
                result.rule_ids.append(wid)
                result.rule_count += 1

    if rule_elements:
        result.xml = _prettify_rules(rule_elements)
    elif not result.errors and not result.skipped:
        result.warnings.append("No Wazuh rules generated from this Sigma rule.")

    result.mitre_techniques = extract_mitre_ids(rule.tags)
    result.tactics = extract_tactics(rule.tags)

    # Persist ID mappings
    if config.id_tracker:
        config.id_tracker.save()

    return result


# ── Batch converter ────────────────────────────────────────────────────────────

def convert_batch(yaml_str: str, config: ConversionConfig) -> List[ConversionResult]:
    """
    Convert a multi-document YAML file.
    Returns one ConversionResult per Sigma rule document.
    ID allocation is sequential across the entire batch.
    """
    rules = parse_multi(yaml_str)
    if not rules:
        return []

    allocator = _IDAllocator(config.rule_id_start, config.id_tracker)
    results: List[ConversionResult] = []

    for rule_idx, rule in enumerate(rules, 1):
        sub_result = ConversionResult(
            sigma_id=rule.id,
            sigma_title=rule.title or f"Rule {rule_idx}",
            sigma_level=rule.level,
            sigma_status=rule.status,
            errors=list(rule.errors),
            warnings=list(rule.warnings),
        )

        if rule.errors:
            results.append(sub_result)
            continue

        try:
            rule_elements: List[Element] = []

            for condition_str in rule.conditions:
                tokens = _tokenize(condition_str)
                skip = _should_skip(rule, condition_str, config)
                if skip:
                    sub_result.skipped.append(skip)
                    continue

                logic_paths = _build_logic_paths(tokens, rule.detection)
                product = resolve_product(rule.logsource)
                level_int = config.get_level(rule.level)

                for path in logic_paths:
                    wid = allocator.allocate(rule.id or "unknown")
                    el = build_rule_element(
                        rule_id=wid,
                        sigma_rule=rule,
                        condition_tokens=path,
                        detection=rule.detection,
                        product=product,
                        level_int=level_int,
                        config=config,
                    )
                    if el is not None:
                        rule_elements.append(el)
                        sub_result.rule_ids.append(wid)
                        sub_result.rule_count += 1

            if rule_elements:
                sub_result.xml = _prettify_rules(rule_elements)

            sub_result.mitre_techniques = extract_mitre_ids(rule.tags)
            sub_result.tactics = extract_tactics(rule.tags)

        except Exception as exc:
            sub_result.errors.append(
                f"Rule {rule_idx} ({rule.title or 'untitled'}): unexpected error — {type(exc).__name__}: {exc}"
            )

        results.append(sub_result)

    if config.id_tracker:
        config.id_tracker.save()

    return results


def merge_results_xml(results: List[ConversionResult]) -> str:
    """Merge all ConversionResult XMLs into a single <group> document."""
    all_rule_blocks: List[str] = []
    for r in results:
        if r.xml:
            # Extract each <rule>...</rule> block intact (preserves inner elements
            # like <group>, <mitre>, and per-rule metadata comments)
            blocks = re.findall(r"<rule\b.*?</rule>", r.xml, flags=re.DOTALL)
            for block in blocks:
                lines = block.strip().split("\n")
                # The regex strips the leading 4-space indent from the opening <rule> tag;
                # restore it so <rule> nests correctly inside the outer <group>.
                lines[0] = "    " + lines[0]
                all_rule_blocks.append("\n".join(lines))

    header = "<group name=\"sigma,\">\n<!-- Generated by SigWaz -->\n"
    body = "\n\n".join(all_rule_blocks)
    return header + body + "\n</group>"


def predict_id_range(count: int, config: ConversionConfig) -> tuple[int, int]:
    """Return (first_id, last_id) for a batch of `count` rules."""
    start = config.rule_id_start + 1
    return start, start + count - 1
