"""
SigWaz XML Splitter — splits large Wazuh rule XML files into
multiple numbered files so the Wazuh manager doesn't OOM on import.
"""
from __future__ import annotations
import re
from typing import List


_RULE_BLOCK_RE = re.compile(
    r"(<rule\b[^>]*>.*?</rule>)",
    re.DOTALL,
)

_GROUP_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<group name=\"sigma,\">\n"
    "<!--\n"
    "  SigWaz — Sigma to Wazuh converter\n"
    "  Sigma: https://github.com/SigmaHQ/sigma\n"
    "  Wazuh: https://wazuh.com\n"
    "-->\n"
)
_GROUP_FOOTER = "\n</group>"


def split_xml(xml_str: str, max_rules: int = 500) -> List[str]:
    """
    Split a Wazuh XML rule file into chunks of at most `max_rules` rules each.

    Returns a list of XML strings, each a complete <group> document.
    If `max_rules` <= 0 or the file has fewer rules than the limit, returns [xml_str].
    """
    if max_rules <= 0:
        return [xml_str]

    rule_blocks = _RULE_BLOCK_RE.findall(xml_str)
    if len(rule_blocks) <= max_rules:
        return [xml_str]

    chunks: List[str] = []
    for i in range(0, len(rule_blocks), max_rules):
        batch = rule_blocks[i : i + max_rules]
        body = "\n\n    ".join(b.strip() for b in batch)
        chunk = _GROUP_HEADER + "    " + body + _GROUP_FOOTER
        chunks.append(chunk)

    return chunks


def split_results_xml(merged_xml: str, max_rules: int = 500) -> List[str]:
    """Convenience wrapper: split an already-merged multi-rule XML string."""
    return split_xml(merged_xml, max_rules)


def filename_for_chunk(base: str, index: int, total: int) -> str:
    """
    Generate a sequential filename like `sigma_rules-1.xml`.
    `base` is the stem without extension (e.g. 'sigma_rules').
    `index` is 0-based.
    `total` is unused (kept for backwards compatibility).
    """
    return f"{base}-{index + 1}.xml"
