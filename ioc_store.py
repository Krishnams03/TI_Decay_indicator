"""
JSON-backed IOC database — load, save, query, and purge.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from models import IOC


class IOCStore:
    """In-memory IOC store backed by a JSON file."""

    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._iocs: Dict[str, IOC] = {}          # keyed by IOC value

    # ── Persistence ──────────────────────────────────────────────────────

    def load(self) -> None:
        """Load IOCs from the JSON database on disk."""
        if not os.path.exists(self._path):
            self._iocs = {}
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self._iocs = {d["value"]: IOC.from_dict(d) for d in data}

    def save(self) -> None:
        """Persist current IOCs to the JSON database."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump([ioc.to_dict() for ioc in self._iocs.values()],
                      fh, indent=2)

    # ── CRUD ─────────────────────────────────────────────────────────────

    def add_ioc(self, ioc: IOC) -> None:
        self._iocs[ioc.value] = ioc

    def get_ioc(self, value: str) -> Optional[IOC]:
        return self._iocs.get(value)

    def get_all(self) -> List[IOC]:
        return list(self._iocs.values())

    def remove_ioc(self, value: str) -> None:
        self._iocs.pop(value, None)

    # ── Bulk operations ──────────────────────────────────────────────────

    def get_stale(self) -> List[IOC]:
        """Return all IOCs currently flagged as stale."""
        return [ioc for ioc in self._iocs.values() if ioc.is_stale]

    def remove_stale(self) -> List[IOC]:
        """Remove and return all stale IOCs from the store."""
        stale = self.get_stale()
        for ioc in stale:
            del self._iocs[ioc.value]
        return stale

    def __len__(self) -> int:
        return len(self._iocs)

    def __repr__(self) -> str:
        return f"IOCStore({len(self)} indicators)"
