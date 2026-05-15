"""
SigWaz ID Tracker — persists Sigma GUID → Wazuh rule ID mappings across runs.
Ensures rule IDs remain stable between re-conversions of the same Sigma rule.
"""
from __future__ import annotations
import json
import os
from typing import Dict, List, Optional, Set


class IDTracker:
    def __init__(self, filepath: Optional[str] = None):
        self._path = filepath
        self._map: Dict[str, List[int]] = {}
        self._all_used: Set[int] = set()
        if filepath and os.path.exists(filepath):
            self._load()

    def _load(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            # Support both int and str IDs in the JSON
            self._map = {
                k: [int(i) for i in v] for k, v in raw.items()
            }
            for ids in self._map.values():
                self._all_used.update(ids)
        except Exception:
            self._map = {}
            self._all_used = set()

    def save(self) -> None:
        if not self._path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._map, f, indent=2)

    def get_ids(self, sigma_guid: str) -> List[int]:
        return list(self._map.get(sigma_guid, []))

    def is_used(self, wazuh_id: int) -> bool:
        return wazuh_id in self._all_used

    def add_mapping(self, sigma_guid: str, wazuh_id: int) -> None:
        if sigma_guid not in self._map:
            self._map[sigma_guid] = []
        if wazuh_id not in self._map[sigma_guid]:
            self._map[sigma_guid].append(wazuh_id)
        self._all_used.add(wazuh_id)

    def all_used_ids(self) -> Set[int]:
        return set(self._all_used)

    def sigma_guid_count(self) -> int:
        return len(self._map)

    def total_rule_count(self) -> int:
        return sum(len(v) for v in self._map.values())

    @classmethod
    def in_memory(cls) -> "IDTracker":
        return cls(filepath=None)
