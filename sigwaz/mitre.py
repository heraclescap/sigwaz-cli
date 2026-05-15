"""
SigWaz MITRE ATT&CK tag extractor.
Parses Sigma `tags` into technique IDs and category labels.
"""
from __future__ import annotations
import re
from typing import List, Tuple

# Matches attack.tNNNN or attack.tNNNN.NNN (sub-techniques)
_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
# Non-technique attack tags (tactics / categories)
_TACTIC_RE = re.compile(
    r"attack\.(execution|persistence|privilege_escalation|defense_evasion|"
    r"credential_access|discovery|lateral_movement|collection|"
    r"command_and_control|exfiltration|impact|reconnaissance|"
    r"resource_development|initial_access)",
    re.IGNORECASE,
)


def extract_mitre_ids(tags: List[str]) -> List[str]:
    """
    Extract MITRE ATT&CK technique IDs from Sigma tags.
    Returns uppercased IDs like ['T1059.001', 'T1105'].
    Only technique tags (attack.tNNNN) are returned — tactics are excluded.
    """
    ids: list[str] = []
    for tag in (tags or []):
        m = _TECHNIQUE_RE.search(tag)
        if m:
            ids.append(m.group(1).upper())
    return ids


def extract_tactics(tags: List[str]) -> List[str]:
    """
    Extract MITRE ATT&CK tactic names from Sigma tags.
    Returns strings like ['execution', 'defense_evasion'].
    """
    tactics: list[str] = []
    for tag in (tags or []):
        m = _TACTIC_RE.search(tag)
        if m:
            tactic = m.group(1).lower()
            if tactic not in tactics:
                tactics.append(tactic)
    return tactics


def extract_all(tags: List[str]) -> Tuple[List[str], List[str]]:
    """Return (technique_ids, tactics) from a list of Sigma tags."""
    return extract_mitre_ids(tags), extract_tactics(tags)
