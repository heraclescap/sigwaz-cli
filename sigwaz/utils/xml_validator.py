"""
SigWaz XML Validator — native XML validation using stdlib xml.etree.
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    rule_count: int = 0
    duplicate_ids: List[str] = field(default_factory=list)


def validate_xml(xml_str: str) -> ValidationResult:
    result = ValidationResult(valid=False)

    if not xml_str or not xml_str.strip():
        result.errors.append("Empty XML output")
        return result

    # 1. Well-formed XML check
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        result.errors.append(f"XML parse error: {exc}")
        return result

    # 2. Root element check
    if root.tag != "group":
        result.warnings.append(f"Expected root tag <group>, got <{root.tag}>")

    # 3. Rule structure validation
    seen_ids: set[str] = set()
    for rule_el in root.findall("rule"):
        rule_id = rule_el.get("id", "")
        rule_level = rule_el.get("level", "")
        result.rule_count += 1

        if not rule_id:
            result.errors.append("Found <rule> element without id attribute")
        elif rule_id in seen_ids:
            result.duplicate_ids.append(rule_id)
            result.errors.append(f"Duplicate rule ID: {rule_id}")
        else:
            seen_ids.add(rule_id)

        if not rule_level:
            result.warnings.append(f"Rule {rule_id} has no level attribute")
        else:
            try:
                lvl = int(rule_level)
                if not (0 <= lvl <= 15):
                    result.warnings.append(
                        f"Rule {rule_id} level {lvl} is outside Wazuh range [0-15]"
                    )
            except ValueError:
                result.errors.append(f"Rule {rule_id} has non-integer level: {rule_level}")

        # Check for required <description>
        if rule_el.find("description") is None:
            result.warnings.append(f"Rule {rule_id} is missing <description>")

        # Check for at least one <field> or <if_sid>/<if_group>
        has_field = rule_el.find("field") is not None
        has_if = (
            rule_el.find("if_sid") is not None
            or rule_el.find("if_group") is not None
        )
        if not has_field:
            result.warnings.append(
                f"Rule {rule_id} has no <field> elements — may match too broadly"
            )

    result.valid = len(result.errors) == 0
    return result
