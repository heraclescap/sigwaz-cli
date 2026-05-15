"""
SigWaz Wazuh XML Builder.
Constructs a Wazuh <rule> XML element from parsed Sigma data and config.
"""
from __future__ import annotations
import re
import base64
from typing import Any, Dict, List, Optional, Tuple
from xml.etree.ElementTree import Element, SubElement, Comment

from .field_maps import get_field_name
from .sid_maps import get_if_sid, get_if_group, resolve_product
from .mitre import extract_mitre_ids


# ── Regex utilities ─────────────────────────────────────────────────────────

def _re_escape(value: str) -> str:
    return re.escape(str(value))


def _fix_value(value: str) -> str:
    """
    Post-process an escaped regex value:
    - \\? → .  (any char wildcard)
    - \\* → .+ (zero-or-more wildcard, after escape)
    - \\\\+ → \\\\+ (collapsed double-backslash sequences)
    """
    value = str(value)
    value = value.replace(r"\?", ".")
    value = value.replace(r"\\", r"\\+")
    value = re.sub(r"(?:\\\\\\+){2,}", r"\\\\+", value)
    value = value.replace(r"\*", ".+")
    return value


def _wrap_case_insensitive(value: str, is_b64: bool = False) -> str:
    if is_b64:
        return value
    # Avoid double-wrapping raw regexes that already contain (?i)
    if value.startswith("(?i)"):
        return value
    # Wrap trailing-space patterns to avoid PCRE2 trimming
    if value.endswith(" "):
        value = f"(?:{value})"
    return f"(?i){value}"


def _handle_b64_offsets(value: str) -> str:
    o1 = base64.b64encode(value.encode()).decode().rstrip("=")
    o2 = base64.b64encode((" " + value).encode()).decode()[2:].rstrip("=")
    o3 = base64.b64encode(("  " + value).encode()).decode()[3:].rstrip("=")
    return f"{o1}|{o2}|{o3}"


def _handle_b64_offsets_list(values: List[str]) -> str:
    parts: List[str] = []
    for v in values:
        parts.append(_handle_b64_offsets(v))
    return "|".join(parts)


# ── Transform handlers ───────────────────────────────────────────────────────

def _apply_transform(
    key: str,
    value: Any,
    negate: bool,
    product: str,
    field_overrides: Optional[Dict[str, Dict[str, str]]] = None,
) -> Tuple[str, List[str], bool]:
    """
    Given a Sigma detection key (possibly with | modifiers) and value,
    return (field_name, [pcre2_patterns], is_base64).

    negate=True means these patterns will have negate="yes" on the <field> element.
    For OR-to-AND splits (contains|all, negate), each value becomes its own pattern.
    """
    is_b64 = False
    transform = ""

    if "|" in key:
        parts = key.split("|", 1)
        field = parts[0]
        transform = parts[1].lower()
    else:
        field = key

    wazuh_field = get_field_name(product, field, field_overrides)
    is_full_log = wazuh_field == "full_log"

    def to_list(v: Any) -> List[Any]:
        if isinstance(v, list):
            return v
        return [v]

    vals = to_list(value)

    # ── base64 / base64offset ────────────────────────────────────────────
    if transform in ("base64", "base64|contains"):
        patterns = [
            base64.b64encode(str(v).encode()).decode().rstrip("=") for v in vals
        ]
        return wazuh_field, patterns, True

    if transform in ("base64offset|contains",):
        if len(vals) == 1:
            return wazuh_field, [_handle_b64_offsets(str(vals[0]))], True
        return wazuh_field, [_handle_b64_offsets_list([str(v) for v in vals])], True

    # ── windash ──────────────────────────────────────────────────────────
    if "windash" in transform:
        vals = [str(v).replace("-", "[/-]") for v in vals]
        transform = transform.replace("windash", "").strip("|")

    # ── re (raw regex) ───────────────────────────────────────────────────
    if transform == "re":
        patterns = [str(v) for v in vals]
        # OR logic only (each value is its own alternative)
        if not negate and len(patterns) > 1:
            return wazuh_field, ["|".join(patterns)], False
        return wazuh_field, patterns, False

    # ── exact match (no modifier, mapped field) ──────────────────────────
    if not transform:
        if is_full_log:
            escaped = [_fix_value(_re_escape(str(v))) for v in vals]
        else:
            escaped = [f"^{_fix_value(_re_escape(str(v)))}$" for v in vals]
        if not negate and len(escaped) > 1:
            return wazuh_field, ["|".join(escaped)], False
        return wazuh_field, escaped, False

    # ── contains ────────────────────────────────────────────────────────
    if transform == "contains":
        escaped = [_fix_value(_re_escape(str(v))) for v in vals]
        if not negate:
            return wazuh_field, ["|".join(escaped)], False
        # negate → one <field negate="yes"> per value
        return wazuh_field, escaped, False

    # ── contains|all ────────────────────────────────────────────────────
    if transform in ("contains|all", "all"):
        escaped = [_fix_value(_re_escape(str(v))) for v in vals]
        # Always one element per value (AND semantics in Wazuh = multiple elements)
        return wazuh_field, escaped, False

    # ── startswith ──────────────────────────────────────────────────────
    if transform == "startswith":
        escaped = [f"^(?:{_fix_value(_re_escape(str(v)))})" for v in vals]
        if not negate:
            return wazuh_field, ["|".join(escaped)], False
        return wazuh_field, escaped, False

    # ── endswith ────────────────────────────────────────────────────────
    if transform == "endswith":
        escaped = [f"(?:{_fix_value(_re_escape(str(v)))})$" for v in vals]
        if not negate:
            return wazuh_field, ["|".join(escaped)], False
        return wazuh_field, escaped, False

    # Unknown transform → fallback to contains
    escaped = [_fix_value(_re_escape(str(v))) for v in vals]
    if not negate:
        return wazuh_field, ["|".join(escaped)], False
    return wazuh_field, escaped, False


# ── Field element appender ───────────────────────────────────────────────────

def _add_field_elements(
    rule_el: Element,
    wazuh_field: str,
    patterns: List[str],
    negate: bool,
    is_b64: bool,
    transform: str = "",
) -> None:
    """Append one or more <field> elements to a rule XML element."""
    # For contains|all each pattern becomes its own element (AND logic)
    # For OR patterns, they are already joined with |
    elements_needed = len(patterns) if (negate or "all" in transform) else 1
    if elements_needed == 1 and len(patterns) > 1:
        patterns = ["|".join(patterns)]

    for pat in patterns:
        el = SubElement(rule_el, "field")
        el.set("name", wazuh_field)
        if negate:
            el.set("negate", "yes")
        el.set("type", "pcre2")
        el.text = _wrap_case_insensitive(pat, is_b64)


# ── Detection traversal ──────────────────────────────────────────────────────

def _process_detection_item(
    rule_el: Element,
    det_item: Any,
    negate: bool,
    product: str,
    field_overrides: Optional[Dict[str, Dict[str, str]]],
) -> None:
    """Recursively process a detection item (dict or list of dicts)."""
    if isinstance(det_item, dict):
        for key, value in det_item.items():
            transform = key.split("|", 1)[1].lower() if "|" in key else ""
            wazuh_field, patterns, is_b64 = _apply_transform(
                key, value, negate, product, field_overrides
            )
            _add_field_elements(rule_el, wazuh_field, patterns, negate, is_b64, transform)

    elif isinstance(det_item, list):
        # List of dicts → treat each dict as an alternative condition piece
        for item in det_item:
            if isinstance(item, dict):
                _process_detection_item(rule_el, item, negate, product, field_overrides)
            else:
                # keyword → search in full_log
                el = SubElement(rule_el, "field")
                el.set("name", "full_log")
                if negate:
                    el.set("negate", "yes")
                el.set("type", "pcre2")
                el.text = _wrap_case_insensitive(_fix_value(_re_escape(str(item))))


# ── Main rule builder ─────────────────────────────────────────────────────────

def build_rule_element(
    rule_id: int,
    sigma_rule,           # SigmaRule
    condition_tokens: List[str],
    detection: Dict[str, Any],
    product: str,
    level_int: int,
    config,               # ConversionConfig
) -> Optional[Element]:
    """
    Build a single Wazuh <rule> XML Element from one logic path.
    Returns None if the path cannot be represented.
    """
    rule_el = Element("rule")
    rule_el.set("id", str(rule_id))
    rule_el.set("level", str(level_int))

    # ── info links (only for explicit http/https reference URLs) ─────────
    for ref_url in (sigma_rule.references or []):
        ref_url = str(ref_url).strip()
        if ref_url.startswith(("http://", "https://")):
            link_el = SubElement(rule_el, "info")
            link_el.set("type", "link")
            link_el.text = ref_url

    # ── metadata comments ────────────────────────────────────────────────
    def _clean_comment(s: str) -> str:
        return s.replace("--", " - ").replace("\r\n", " ").replace("\n", " ").replace("\r", " ").strip()

    if sigma_rule.author:
        rule_el.append(Comment(f" Author: {_clean_comment(sigma_rule.author)} "))
    if sigma_rule.description:
        rule_el.append(Comment(f" Description: {_clean_comment(sigma_rule.description)} "))
    if sigma_rule.date:
        rule_el.append(Comment(f" Date: {sigma_rule.date} "))
    if sigma_rule.status:
        rule_el.append(Comment(f" Status: {sigma_rule.status} "))
    if sigma_rule.id:
        rule_el.append(Comment(f" Sigma ID: {sigma_rule.id} "))
    if sigma_rule.references:
        refs_str = " | ".join(str(r) for r in sigma_rule.references)
        rule_el.append(Comment(f" References: {_clean_comment(refs_str)} "))

    # ── if_group / if_sid ────────────────────────────────────────────────
    logsource = sigma_rule.logsource or {}
    if_group_val = get_if_group(logsource, config.if_group_overrides)
    if if_group_val:
        ig_el = SubElement(rule_el, "if_group")
        ig_el.text = if_group_val
    else:
        if_sid_val = get_if_sid(logsource, config.if_sid_overrides)
        if if_sid_val:
            is_el = SubElement(rule_el, "if_sid")
            is_el.text = if_sid_val

    # ── detection fields ─────────────────────────────────────────────────
    _process_condition_tokens(
        rule_el,
        condition_tokens,
        detection,
        product,
        config.field_map_overrides,
    )

    # ── description ──────────────────────────────────────────────────────
    desc_el = SubElement(rule_el, "description")
    desc_el.text = sigma_rule.title

    # ── options ──────────────────────────────────────────────────────────
    if config.no_full_log:
        opt = SubElement(rule_el, "options")
        opt.text = "no_full_log"

    email_needed = (
        config.email_alert and sigma_rule.level in (config.email_levels or [])
    ) or (sigma_rule.id in (config.sigma_guid_email or []))
    if email_needed:
        opt = SubElement(rule_el, "options")
        opt.text = "alert_by_email"

    # ── group (logsource values) ─────────────────────────────────────────
    group_parts: List[str] = []
    for key in ("product", "category", "service"):
        val = logsource.get(key)
        if val and val.lower() not in ("", "definition"):
            group_parts.append(val.lower().replace(" ", "_"))
    if group_parts:
        group_el = SubElement(rule_el, "group")
        group_el.text = ",".join(group_parts) + ","

    # ── MITRE (always last) ───────────────────────────────────────────────
    mitre_ids = extract_mitre_ids(sigma_rule.tags)
    if mitre_ids:
        mitre_el = SubElement(rule_el, "mitre")
        for tid in mitre_ids:
            id_el = SubElement(mitre_el, "id")
            id_el.text = tid

    return rule_el


def _process_condition_tokens(
    rule_el: Element,
    tokens: List[str],
    detection: Dict[str, Any],
    product: str,
    field_overrides: Optional[Dict[str, Dict[str, str]]],
) -> None:
    """Walk condition tokens and add <field> elements to rule_el."""
    negate = False
    i = 0
    while i < len(tokens):
        ref = tokens[i]
        tok = ref.lower()

        # Entries from _build_logic_paths carry a "not:" prefix for negated refs
        if tok.startswith("not:"):
            negate = True
            ref = ref[4:]
            tok = ref.lower()

        if tok == "not":
            negate = True
            i += 1
            continue
        if tok in ("and", "or", "(", ")"):
            i += 1
            continue
        if tok.startswith("1_of") or tok.startswith("all_of"):
            i += 1
            continue
        # tok is a detection reference name
        det_item = detection.get(tok) or detection.get(ref)
        if det_item is not None and tok != "condition":
            _process_detection_item(
                rule_el, det_item, negate, product, field_overrides
            )
        negate = False
        i += 1
