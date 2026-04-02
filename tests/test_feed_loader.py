"""Unit tests for feed_loader module — live feed parsers with mocked HTTP."""

import sys
import os
from datetime import datetime
from unittest.mock import patch, MagicMock
import requests as requests_lib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import IOC, IndicatorType
from feed_loader import (
    _normalise_type,
    _parse_timestamp,
    _map_severity,
    load_sample_feed,
    load_otx_feed,
    load_threatfox_feed,
    load_urlhaus_feed,
    load_live_feed,
    get_feed_status,
)


# ── Type normalization ───────────────────────────────────────────────────────

def test_normalise_type_ip():
    assert _normalise_type("ip") == IndicatorType.IP
    assert _normalise_type("IPv4") == IndicatorType.IP
    assert _normalise_type("ip:port") == IndicatorType.IP

def test_normalise_type_domain():
    assert _normalise_type("domain") == IndicatorType.DOMAIN
    assert _normalise_type("hostname") == IndicatorType.DOMAIN

def test_normalise_type_hash():
    assert _normalise_type("sha256") == IndicatorType.FILE_HASH
    assert _normalise_type("FileHash-SHA256") == IndicatorType.FILE_HASH

def test_normalise_type_unknown_defaults_ip():
    assert _normalise_type("unknown_type") == IndicatorType.IP


# ── Timestamp parsing ────────────────────────────────────────────────────────

def test_parse_timestamp_utc_format():
    ts = _parse_timestamp("2026-02-01 08:00:00 UTC")
    assert ts == datetime(2026, 2, 1, 8, 0, 0)

def test_parse_timestamp_iso_format():
    ts = _parse_timestamp("2026-02-01T08:00:00")
    assert ts == datetime(2026, 2, 1, 8, 0, 0)

def test_parse_timestamp_bad_string_returns_now():
    ts = _parse_timestamp("not-a-date")
    assert isinstance(ts, datetime)


# ── Severity mapping ─────────────────────────────────────────────────────────

def test_map_severity_botnet():
    assert _map_severity("botnet_c2") == _map_severity("Botnet C2")

def test_map_severity_high_confidence():
    from models import Severity
    assert _map_severity("generic", confidence=85) == Severity.HIGH

def test_map_severity_low_confidence():
    from models import Severity
    assert _map_severity("generic", confidence=30) == Severity.LOW


# ── OTX feed (mocked) ───────────────────────────────────────────────────────

@patch("feed_loader.OTX_API_KEY", "test-key-123")
@patch("feed_loader.requests.get")
def test_load_otx_feed_parses_pulses(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "results": [
            {
                "name": "Test Pulse",
                "created": "2026-02-01T10:00:00",
                "tlp": "green",
                "adversary": "",
                "description": "Test APT activity",
                "indicators": [
                    {"type": "IPv4", "indicator": "192.168.1.100", "created": "2026-02-01T10:00:00", "description": ""},
                    {"type": "domain", "indicator": "evil.example.com", "created": "2026-02-01T11:00:00", "description": ""},
                    {"type": "CIDR", "indicator": "10.0.0.0/8", "created": "", "description": ""},  # should be skipped
                ],
            }
        ]
    }
    mock_get.return_value = mock_resp

    iocs = load_otx_feed(limit=10, days=7)
    assert len(iocs) == 2
    assert iocs[0].indicator_type == IndicatorType.IP
    assert iocs[0].source == "alienvault_otx"
    assert iocs[1].indicator_type == IndicatorType.DOMAIN


@patch("feed_loader.OTX_API_KEY", "")
def test_load_otx_feed_no_key_returns_empty():
    result = load_otx_feed()
    assert result == []


@patch("feed_loader.OTX_API_KEY", "test-key")
@patch("feed_loader.requests.get", side_effect=requests_lib.RequestException("Network error"))
def test_load_otx_feed_network_error_returns_empty(mock_get):
    result = load_otx_feed()
    assert result == []


# ── ThreatFox feed (mocked) ─────────────────────────────────────────────────

@patch("feed_loader.ABUSECH_AUTH_KEY", "test-abuse-key")
@patch("feed_loader.requests.post")
def test_load_threatfox_feed_parses_iocs(mock_post):
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [
            {
                "ioc_type": "ip:port",
                "ioc_value": "203.0.113.5:443",
                "confidence_level": 80,
                "first_seen_utc": "2026-02-10 12:00:00 UTC",
                "threat_type": "botnet_cc",
                "malware": "Emotet",
                "reporter": "abuse_ch",
            },
            {
                "ioc_type": "domain",
                "ioc_value": "malware.example.com",
                "confidence_level": 60,
                "first_seen_utc": "2026-02-11 08:00:00 UTC",
                "threat_type": "phishing",
                "malware": "",
                "reporter": "",
            },
        ]
    }
    mock_post.return_value = mock_resp

    iocs = load_threatfox_feed(days=1, limit=10)
    assert len(iocs) == 2
    assert iocs[0].value == "203.0.113.5"  # port stripped
    assert iocs[0].source == "threatfox"
    assert iocs[1].indicator_type == IndicatorType.DOMAIN


@patch("feed_loader.ABUSECH_AUTH_KEY", "")
def test_load_threatfox_feed_no_key_returns_empty():
    result = load_threatfox_feed()
    assert result == []


# ── URLhaus feed (mocked) ───────────────────────────────────────────────────

@patch("feed_loader.ABUSECH_AUTH_KEY", "test-abuse-key")
@patch("feed_loader.requests.get")
def test_load_urlhaus_feed_parses_urls(mock_get):
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "urls": [
            {"url": "http://evil.com/payload.exe", "date_added": "2026-02-10 12:00:00 UTC", "threat": "malware_download", "url_status": "online"},
            {"url": "http://phish.example.com/login", "date_added": "2026-02-11 08:00:00 UTC", "threat": "phishing", "url_status": "offline"},
        ]
    }
    mock_get.return_value = mock_resp

    iocs = load_urlhaus_feed(limit=10)
    assert len(iocs) == 2
    assert all(ioc.indicator_type == IndicatorType.URL for ioc in iocs)
    assert iocs[0].current_confidence == 90.0   # online
    assert iocs[1].current_confidence == 55.0   # offline
    assert iocs[0].source == "urlhaus"


@patch("feed_loader.ABUSECH_AUTH_KEY", "")
def test_load_urlhaus_feed_no_key_returns_empty():
    result = load_urlhaus_feed()
    assert result == []


# ── Orchestrator ─────────────────────────────────────────────────────────────

@patch("feed_loader.OTX_API_KEY", "test-key")
@patch("feed_loader.ABUSECH_AUTH_KEY", "")
def test_get_feed_status():
    status = get_feed_status()
    assert status["otx"]["configured"] is True
    assert status["threatfox"]["configured"] is False
    assert status["urlhaus"]["configured"] is False


@patch("feed_loader.ABUSECH_AUTH_KEY", "")
@patch("feed_loader.OTX_API_KEY", "test-key")
def test_load_live_feed_deduplicates():
    ioc1 = IOC(
        value="1.2.3.4", indicator_type=IndicatorType.IP,
        initial_confidence=80, current_confidence=80,
        first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1),
        source="alienvault_otx",
    )
    mock_fn = MagicMock(return_value=[ioc1, ioc1])

    with patch.dict("feed_loader.FEED_FUNCTIONS", {"otx": mock_fn}):
        result = load_live_feed(sources=["otx"], limit=50)
    assert len(result) == 1  # deduplicated


@patch("feed_loader.OTX_API_KEY", "")
@patch("feed_loader.ABUSECH_AUTH_KEY", "")
def test_load_live_feed_no_keys_returns_empty():
    result = load_live_feed()
    assert result == []


# ── Sample feed (existing) ──────────────────────────────────────────────────

def test_load_sample_feed():
    from config import SAMPLE_FEED_PATH
    if os.path.exists(SAMPLE_FEED_PATH):
        iocs = load_sample_feed(SAMPLE_FEED_PATH)
        assert len(iocs) > 0
        assert all(isinstance(ioc, IOC) for ioc in iocs)


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
