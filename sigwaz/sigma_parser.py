"""
SigWaz Sigma YAML Parser.
Parses raw YAML text into a structured SigmaRule dataclass.
Supports single rules and multi-document YAML (--- separator).
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ruamel.yaml import YAML

_yaml = YAML(typ="safe")

# ── Error sanitization ────────────────────────────────────────────────────────

def _sanitize_yaml_error(exc: Exception) -> str:
    """
    Convert a ruamel.yaml exception into a safe, user-friendly message.
    Never exposes stack traces, file paths, or full parser internals.
    """
    msg = str(exc)

    # Duplicate key — most common user mistake when pasting two rules without ---
    if "duplicate key" in msg.lower():
        m = re.search(r'duplicate key "([^"]{1,80})"', msg)
        key = f'"{m.group(1)}"' if m else "a field"
        return (
            f"YAML error: duplicate key {key}. "
            "If you have multiple rules, separate them with '---' on its own line."
        )

    # Extract line/column from ruamel mark objects (safe — no user content)
    for attr in ("context_mark", "problem_mark"):
        mark = getattr(exc, attr, None)
        if mark is not None:
            line = getattr(mark, "line", None)
            col  = getattr(mark, "column", None)
            if line is not None:
                kind = "Mapping" if "mapping" in msg.lower() else "Syntax"
                return f"YAML {kind} error at line {line + 1}, column {(col or 0) + 1}"

    # Fallback — no internal details
    return "YAML syntax error — check rule formatting and indentation"


@dataclass
class SigmaRule:
    raw: Dict[str, Any]
    title: str = ""
    id: str = ""
    status: str = ""
    description: str = ""
    author: str = ""
    date: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    logsource: Dict[str, str] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    falsepositives: List[str] = field(default_factory=list)
    level: str = "medium"
    # Parsed conditions (after fixup)
    conditions: List[str] = field(default_factory=list)
    # Validation
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _fixup_condition(cond: Any) -> List[str]:
    """Normalize condition to a list of strings with tokens space-normalized."""
    replacements = [
        ("1 of them", "1_of_them"),
        ("all of them", "all_of_them"),
        ("1 of ", "1_of "),
        ("all of ", "all_of "),
        ("(", " ( "),
        (")", " ) "),
    ]
    def _fix(s: str) -> str:
        for old, new in replacements:
            s = s.replace(old, new)
        # Collapse duplicate spaces
        return re.sub(r" {2,}", " ", s).strip()

    if isinstance(cond, list):
        return [_fix(str(c)) for c in cond]
    return [_fix(str(cond))]


def parse_rule(raw_yaml: str) -> SigmaRule:
    """Parse a single Sigma YAML document into a SigmaRule."""
    errors: List[str] = []
    warnings: List[str] = []

    # Normalize line endings so \r\n and \n are treated identically
    raw_yaml = raw_yaml.replace("\r\n", "\n").replace("\r", "\n")

    # Detect accidental multi-doc input sent to the single-rule endpoint
    if re.search(r"^---[ \t]*$", raw_yaml, re.MULTILINE):
        return SigmaRule(
            raw={},
            errors=[
                "Multiple rules detected. Use '---' separators and submit via the batch endpoint, "
                "or enter one rule at a time."
            ],
        )

    try:
        data: Dict[str, Any] = _yaml.load(raw_yaml) or {}
    except Exception as exc:
        return SigmaRule(
            raw={},
            errors=[_sanitize_yaml_error(exc)],
        )

    rule = SigmaRule(raw=data)

    # Mandatory fields
    rule.title = str(data.get("title") or "")
    if not rule.title:
        errors.append("Missing required field: title")

    rule.id = str(data.get("id") or "")
    if not rule.id:
        warnings.append("Missing field: id (rule ID stability not guaranteed)")

    rule.status = str(data.get("status") or "")
    rule.description = str(data.get("description") or "")
    rule.author = str(data.get("author") or "")
    rule.date = str(data.get("date") or "")
    rule.level = str(data.get("level") or "medium").lower()

    # References
    refs = data.get("references")
    if isinstance(refs, list):
        rule.references = [str(r) for r in refs]

    # Tags
    tags = data.get("tags")
    if isinstance(tags, list):
        rule.tags = [str(t) for t in tags]

    # Logsource
    ls = data.get("logsource")
    if isinstance(ls, dict):
        rule.logsource = {str(k): str(v) for k, v in ls.items() if v is not None}
    else:
        errors.append("Missing or invalid logsource")

    # Detection
    det = data.get("detection")
    if isinstance(det, dict):
        rule.detection = det
    else:
        errors.append("Missing or invalid detection")

    # Condition
    if isinstance(det, dict) and "condition" in det:
        raw_cond = det["condition"]
        rule.conditions = _fixup_condition(raw_cond)
    else:
        if not errors:
            errors.append("Missing detection.condition")

    # Falsepositives
    fp = data.get("falsepositives")
    if isinstance(fp, list):
        rule.falsepositives = [str(f) for f in fp]

    rule.errors = errors
    rule.warnings = warnings
    return rule


def _split_yaml_docs(raw_yaml: str) -> List[str]:
    """
    Split a raw YAML string into individual Sigma rule documents.

    Primary strategy: split on '---' document separators.
    Fallback: when no separator is found but multiple root-level 'title:'
    fields exist (rules pasted together without separators), split at each
    new title occurrence.
    """
    if re.search(r"^---[ \t]*$", raw_yaml, re.MULTILINE):
        parts = re.split(r"^---[ \t]*$", raw_yaml, flags=re.MULTILINE)
        return [p.strip() for p in parts if p.strip()]

    positions = [m.start() for m in re.finditer(r"^title[ \t]*:", raw_yaml, re.MULTILINE)]
    if len(positions) <= 1:
        return [raw_yaml.strip()] if raw_yaml.strip() else []

    docs: List[str] = []
    for i, pos in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(raw_yaml)
        doc_text = raw_yaml[pos:end].strip()
        if doc_text:
            docs.append(doc_text)
    return docs


def parse_multi(raw_yaml: str) -> List[SigmaRule]:
    """
    Parse one or more Sigma rules from raw YAML.
    Accepts '---' separated multi-doc YAML or rules pasted side-by-side
    (detected via multiple root-level 'title:' fields).
    """
    raw_yaml = raw_yaml.replace("\r\n", "\n").replace("\r", "\n")
    rules: List[SigmaRule] = []
    for doc in _split_yaml_docs(raw_yaml):
        rules.append(parse_rule(doc))
    return rules
