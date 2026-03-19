"""
Confidence Updater — orchestrates decay, boost, and prioritization across the IOC store.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from models import IOC
from ioc_store import IOCStore
from decay_engine import apply_decay, apply_boost, check_stale


def update_all(store: IOCStore, current_time: datetime) -> None:
    """Apply time-decay to every IOC in *store* and flag stale entries."""
    for ioc in store.get_all():
        apply_decay(ioc, current_time)
        check_stale(ioc)


def reinforce(store: IOCStore, indicator_value: str,
              observation_time: datetime) -> float | None:
    """Boost the confidence of an indicator that was re-observed.

    Returns the new confidence, or ``None`` if the indicator is not in the store.
    """
    ioc = store.get_ioc(indicator_value)
    if ioc is None:
        return None
    return apply_boost(ioc, observation_time)


def get_priority_list(store: IOCStore) -> List[IOC]:
    """Return IOCs sorted by current confidence, highest first."""
    return sorted(store.get_all(),
                  key=lambda i: i.current_confidence, reverse=True)


def get_active_indicators(store: IOCStore) -> List[IOC]:
    """Return only non-stale IOCs, sorted by confidence descending."""
    return [i for i in get_priority_list(store) if not i.is_stale]


def get_stale_indicators(store: IOCStore) -> List[IOC]:
    """Return stale IOCs sorted by confidence ascending (worst first)."""
    return sorted(store.get_stale(),
                  key=lambda i: i.current_confidence)
