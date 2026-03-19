"""Unit tests for ioc_store module."""

import json
import os
import tempfile
from datetime import datetime

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import IOC, IndicatorType
from ioc_store import IOCStore


def _make_ioc(value: str = "1.2.3.4", confidence: float = 80.0,
              stale: bool = False) -> IOC:
    now = datetime(2026, 2, 1)
    return IOC(
        value=value,
        indicator_type=IndicatorType.IP,
        initial_confidence=confidence,
        current_confidence=confidence,
        first_seen=now,
        last_seen=now,
        is_stale=stale,
    )


def test_add_and_get():
    store = IOCStore(os.path.join(tempfile.gettempdir(), "test_db.json"))
    ioc = _make_ioc()
    store.add_ioc(ioc)
    assert store.get_ioc("1.2.3.4") is ioc
    assert len(store) == 1


def test_save_and_load_roundtrip():
    path = os.path.join(tempfile.gettempdir(), "test_roundtrip.json")
    store = IOCStore(path)
    store.add_ioc(_make_ioc("10.0.0.1", 95))
    store.add_ioc(_make_ioc("10.0.0.2", 60))
    store.save()

    store2 = IOCStore(path)
    store2.load()
    assert len(store2) == 2
    loaded = store2.get_ioc("10.0.0.1")
    assert loaded is not None
    assert loaded.initial_confidence == 95

    os.unlink(path)


def test_remove_stale():
    store = IOCStore(os.path.join(tempfile.gettempdir(), "test_stale.json"))
    store.add_ioc(_make_ioc("a", stale=False))
    store.add_ioc(_make_ioc("b", stale=True))
    store.add_ioc(_make_ioc("c", stale=True))

    removed = store.remove_stale()
    assert len(removed) == 2
    assert len(store) == 1
    assert store.get_ioc("a") is not None


def test_get_all():
    store = IOCStore(os.path.join(tempfile.gettempdir(), "test_all.json"))
    store.add_ioc(_make_ioc("x"))
    store.add_ioc(_make_ioc("y"))
    assert len(store.get_all()) == 2


if __name__ == "__main__":
    import inspect
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ✔ {name}")
                passed += 1
            except AssertionError as e:
                print(f"  ✘ {name}  →  {e}")
                failed += 1
    print(f"\n  {passed} passed, {failed} failed")
