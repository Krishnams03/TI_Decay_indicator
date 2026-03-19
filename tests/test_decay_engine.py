"""Unit tests for decay_engine module."""

import math
from datetime import datetime, timedelta

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import IOC, IndicatorType
from decay_engine import (
    calculate_decay,
    apply_decay,
    apply_boost,
    check_stale,
    should_archive,
)
from config import DECAY_CONSTANTS, STALE_THRESHOLD, ARCHIVE_THRESHOLD


def _make_ioc(itype: IndicatorType = IndicatorType.IP,
              confidence: float = 90.0,
              last_seen: datetime | None = None) -> IOC:
    """Helper to build a test IOC."""
    now = last_seen or datetime(2026, 2, 1, 0, 0, 0)
    return IOC(
        value="test-indicator",
        indicator_type=itype,
        initial_confidence=confidence,
        current_confidence=confidence,
        first_seen=now,
        last_seen=now,
    )


# ── calculate_decay ──────────────────────────────────────────────────────

def test_calculate_decay_zero_time():
    """At t=0 confidence should equal C0."""
    assert calculate_decay(90, 0.15, 0) == 90.0


def test_calculate_decay_known_value():
    """Verify against hand-computed value: 90 * e^(-0.15*10)."""
    expected = 90 * math.exp(-0.15 * 10)
    assert abs(calculate_decay(90, 0.15, 10) - expected) < 1e-9


def test_calculate_decay_large_time():
    """After a very long time confidence approaches zero."""
    assert calculate_decay(100, 0.15, 1000) < 0.001


# ── apply_decay ──────────────────────────────────────────────────────────

def test_apply_decay_ip():
    ioc = _make_ioc(IndicatorType.IP, 90)
    ten_days_later = ioc.last_seen + timedelta(days=10)
    new_conf = apply_decay(ioc, ten_days_later)
    expected = 90 * math.exp(-DECAY_CONSTANTS["IP"] * 10)
    assert abs(new_conf - expected) < 0.01


def test_apply_decay_file_hash_slow():
    """File hashes should decay much slower than IPs."""
    ip_ioc   = _make_ioc(IndicatorType.IP, 90)
    hash_ioc = _make_ioc(IndicatorType.FILE_HASH, 90)
    t = ip_ioc.last_seen + timedelta(days=20)
    apply_decay(ip_ioc, t)
    apply_decay(hash_ioc, t)
    assert hash_ioc.current_confidence > ip_ioc.current_confidence


# ── apply_boost ──────────────────────────────────────────────────────────

def test_apply_boost_increases_confidence():
    ioc = _make_ioc(confidence=40.0)
    new = apply_boost(ioc, datetime(2026, 2, 20))
    assert new > 40.0


def test_apply_boost_caps_at_max():
    ioc = _make_ioc(confidence=95.0)
    new = apply_boost(ioc, datetime(2026, 2, 20), alpha=20)
    assert new == 100.0


def test_apply_boost_resets_stale():
    ioc = _make_ioc(confidence=20.0)
    ioc.is_stale = True
    apply_boost(ioc, datetime(2026, 2, 20))
    assert not ioc.is_stale


# ── check_stale / should_archive ─────────────────────────────────────────

def test_check_stale_below_threshold():
    ioc = _make_ioc(confidence=25.0)
    ioc.current_confidence = 25.0
    assert check_stale(ioc) is True
    assert ioc.is_stale is True


def test_check_stale_above_threshold():
    ioc = _make_ioc(confidence=80.0)
    assert check_stale(ioc) is False


def test_should_archive():
    ioc = _make_ioc(confidence=5.0)
    ioc.current_confidence = 5.0
    assert should_archive(ioc) is True


if __name__ == "__main__":
    # Quick runner without pytest
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
