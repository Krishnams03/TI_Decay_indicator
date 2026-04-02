"""
Feed Loader — reads sample, simulation, and LIVE threat feeds, normalizing
them into IOC objects for the decay engine.

╔══════════════════════════════════════════════════════════════════════╗
║  LIVE FEED SOURCES                                                 ║
║                                                                    ║
║  1. AlienVault OTX  — subscribed pulses with multi-type IOCs       ║
║       Requires: OTX_API_KEY  (free)                                ║
║  2. ThreatFox       — community IOCs (IPs, domains, hashes)        ║
║       Requires: ABUSECH_AUTH_KEY  (free)                           ║
║  3. URLhaus         — recent malicious URLs                        ║
║       Requires: ABUSECH_AUTH_KEY  (free)                           ║
║                                                                    ║
║  The local sample feed (data/sample_iocs.json) is still available  ║
║  as a fallback when no API keys are configured.                    ║
╚══════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from models import IOC, IndicatorType, Severity
from config import (
    DEFAULT_INITIAL_CONFIDENCE,
    OTX_API_KEY, ABUSECH_AUTH_KEY,
    OTX_API_URL, THREATFOX_API_URL, URLHAUS_API_URL,
)

logger = logging.getLogger(__name__)

# ── Type mapping helpers ─────────────────────────────────────────────────────

def _normalise_type(raw: str) -> IndicatorType:
    """Map free-form type strings to the IndicatorType enum."""
    mapping = {
        "ip":         IndicatorType.IP,
        "ip_address": IndicatorType.IP,
        "ipv4":       IndicatorType.IP,
        "ipv6":       IndicatorType.IP,
        "ip:port":    IndicatorType.IP,
        "domain":     IndicatorType.DOMAIN,
        "hostname":   IndicatorType.DOMAIN,
        "url":        IndicatorType.URL,
        "hash":       IndicatorType.FILE_HASH,
        "file_hash":  IndicatorType.FILE_HASH,
        "md5":        IndicatorType.FILE_HASH,
        "sha1":       IndicatorType.FILE_HASH,
        "sha256":     IndicatorType.FILE_HASH,
        "filehash-md5":    IndicatorType.FILE_HASH,
        "filehash-sha1":   IndicatorType.FILE_HASH,
        "filehash-sha256": IndicatorType.FILE_HASH,
        "email":      IndicatorType.EMAIL,
    }
    return mapping.get(raw.strip().lower(), IndicatorType.IP)


_OTX_TYPE_MAP: Dict[str, IndicatorType] = {
    "IPv4":     IndicatorType.IP,
    "IPv6":     IndicatorType.IP,
    "domain":   IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "URL":      IndicatorType.URL,
    "FileHash-MD5":    IndicatorType.FILE_HASH,
    "FileHash-SHA1":   IndicatorType.FILE_HASH,
    "FileHash-SHA256": IndicatorType.FILE_HASH,
    "email":    IndicatorType.EMAIL,
}


def _parse_timestamp(raw: str) -> datetime:
    """Parse various timestamp formats into a datetime object."""
    for fmt in (
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    # Fallback: try isoformat
    try:
        return datetime.fromisoformat(raw.strip().replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return datetime.now()


def _map_severity(threat_type: str = "", confidence: float = 50) -> Severity:
    """Infer severity from feed metadata."""
    t = threat_type.lower()
    if any(k in t for k in ("botnet", "ransomware", "c2", "apt", "exploit")):
        return Severity.CRITICAL
    if any(k in t for k in ("trojan", "stealer", "loader", "rat", "backdoor")):
        return Severity.HIGH
    if any(k in t for k in ("phish", "spam", "adware", "pup")):
        return Severity.MEDIUM
    # Fall back to confidence-based
    if confidence >= 80:
        return Severity.HIGH
    if confidence >= 50:
        return Severity.MEDIUM
    return Severity.LOW


# ═══════════════════════════════════════════════════════════════════════════════
#  LOCAL SAMPLE FEED
# ═══════════════════════════════════════════════════════════════════════════════

def load_sample_feed(path: str) -> List[IOC]:
    """Read a JSON threat-feed file and return normalised IOC objects.

    Expected JSON schema (list of objects)::

        [
          {
            "value":       "192.168.1.100",
            "type":        "ip",
            "confidence":  90,
            "first_seen":  "2026-02-01T08:00:00",
            "source":      "sample_feed"
          },
          ...
        ]
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw_list = json.load(fh)

    iocs: List[IOC] = []
    for entry in raw_list:
        first_seen = datetime.fromisoformat(entry["first_seen"])
        confidence = float(entry.get("confidence", DEFAULT_INITIAL_CONFIDENCE))
        ioc = IOC(
            value=entry["value"],
            indicator_type=_normalise_type(entry["type"]),
            initial_confidence=confidence,
            current_confidence=confidence,
            first_seen=first_seen,
            last_seen=first_seen,
            observations=[first_seen],
            is_stale=False,
            source=entry.get("source", "sample_feed"),
        )
        iocs.append(ioc)
    return iocs


# ═══════════════════════════════════════════════════════════════════════════════
#  ALIENVAULT OTX  (Primary — user has API key)
# ═══════════════════════════════════════════════════════════════════════════════

def load_otx_feed(limit: int = 50, days: int = 7) -> List[IOC]:
    """Fetch IOCs from AlienVault OTX subscribed pulses.

    Uses the /pulses/subscribed endpoint to get recent pulse indicators.
    Falls back to /pulses/activity if not subscribed to any pulses.
    """
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping AlienVault OTX feed")
        return []

    headers = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
    iocs: List[IOC] = []
    seen: set = set()

    # Try subscribed pulses first, fall back to activity feed
    endpoints = [
        f"{OTX_API_URL}pulses/subscribed?limit=10&modified_since=",
        f"{OTX_API_URL}pulses/activity?limit=10&modified_since=",
    ]

    # Calculate modified_since date
    from datetime import timedelta
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")

    for endpoint_base in endpoints:
        url = endpoint_base + since
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 403:
                logger.warning("OTX API returned 403 — check your API key")
                continue
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error("OTX request failed: %s", e)
            continue

        pulses = data.get("results", [])
        if not pulses:
            continue

        for pulse in pulses:
            pulse_name = pulse.get("name", "OTX_pulse")
            # TLP / adversary info for reliability scoring
            tlp = pulse.get("tlp", "white").lower()
            reliability = {"red": 0.95, "amber": 0.85, "green": 0.75, "white": 0.65}.get(tlp, 0.7)

            for indicator in pulse.get("indicators", []):
                ioc_type_str = indicator.get("type", "")
                ioc_type = _OTX_TYPE_MAP.get(ioc_type_str)
                if ioc_type is None:
                    continue  # skip unsupported types (e.g., CIDR, mutex)

                value = indicator.get("indicator", "").strip()
                if not value or value in seen:
                    continue
                seen.add(value)

                # Parse timestamps
                created = indicator.get("created", "") or pulse.get("created", "")
                first_seen = _parse_timestamp(created) if created else datetime.now()

                # OTX doesn't have per-indicator confidence, use pulse-level info
                confidence = 75.0  # default for OTX
                if pulse.get("adversary"):
                    confidence = 85.0  # attributed threats are higher confidence
                if tlp in ("red", "amber"):
                    confidence += 5.0

                description = indicator.get("description", "") or pulse.get("description", "")
                severity = _map_severity(description, confidence)

                ioc = IOC(
                    value=value,
                    indicator_type=ioc_type,
                    initial_confidence=round(confidence, 2),
                    current_confidence=round(confidence, 2),
                    first_seen=first_seen,
                    last_seen=first_seen,
                    observations=[first_seen],
                    is_stale=False,
                    source="alienvault_otx",
                    severity=severity,
                    source_reliability=reliability,
                )
                iocs.append(ioc)

                if len(iocs) >= limit:
                    break

            if len(iocs) >= limit:
                break

        if iocs:  # got data from this endpoint, don't try fallback
            break

    logger.info("OTX feed: loaded %d IOCs", len(iocs))
    return iocs


# ═══════════════════════════════════════════════════════════════════════════════
#  THREATFOX  (abuse.ch)
# ═══════════════════════════════════════════════════════════════════════════════

def load_threatfox_feed(days: int = 1, limit: int = 50) -> List[IOC]:
    """Fetch recent IOCs from the ThreatFox API.

    POST to the API with {"query": "get_iocs", "days": N}.
    Each result has: ioc_value, ioc_type, threat_type, confidence_level, first_seen_utc.
    """
    if not ABUSECH_AUTH_KEY:
        logger.warning("ABUSECH_AUTH_KEY not set — skipping ThreatFox feed")
        return []

    headers = {"Auth-Key": ABUSECH_AUTH_KEY, "Content-Type": "application/json"}
    payload = {"query": "get_iocs", "days": days}

    try:
        resp = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        logger.error("ThreatFox request failed: %s", e)
        return []

    if data.get("query_status") != "ok":
        logger.warning("ThreatFox query_status: %s", data.get("query_status"))
        return []

    iocs: List[IOC] = []
    seen: set = set()

    for entry in (data.get("data") or []):
        raw_type = entry.get("ioc_type", "")
        value = entry.get("ioc_value", "").strip()

        # ThreatFox sometimes includes port (ip:port) — strip port for IP type
        if "ip:port" in raw_type.lower() and ":" in value:
            value = value.rsplit(":", 1)[0]

        if not value or value in seen:
            continue
        seen.add(value)

        ioc_type = _normalise_type(raw_type)

        # ThreatFox confidence_level: 0-100
        confidence = float(entry.get("confidence_level", 70))
        # Clamp to our scale
        confidence = max(10.0, min(100.0, confidence))

        first_seen_str = entry.get("first_seen_utc", "")
        first_seen = _parse_timestamp(first_seen_str) if first_seen_str else datetime.now()

        threat_type = entry.get("threat_type", "") or entry.get("malware", "")
        severity = _map_severity(threat_type, confidence)

        # Reporter reliability
        reporter = entry.get("reporter", "")
        reliability = 0.80 if reporter else 0.70

        ioc = IOC(
            value=value,
            indicator_type=ioc_type,
            initial_confidence=round(confidence, 2),
            current_confidence=round(confidence, 2),
            first_seen=first_seen,
            last_seen=first_seen,
            observations=[first_seen],
            is_stale=False,
            source="threatfox",
            severity=severity,
            source_reliability=reliability,
        )
        iocs.append(ioc)

        if len(iocs) >= limit:
            break

    logger.info("ThreatFox feed: loaded %d IOCs", len(iocs))
    return iocs


# ═══════════════════════════════════════════════════════════════════════════════
#  URLHAUS  (abuse.ch)
# ═══════════════════════════════════════════════════════════════════════════════

def load_urlhaus_feed(limit: int = 50) -> List[IOC]:
    """Fetch recent malicious URLs from URLhaus.

    GET /urls/recent/ with Auth-Key header.
    All results are URL-type IOCs.
    """
    if not ABUSECH_AUTH_KEY:
        logger.warning("ABUSECH_AUTH_KEY not set — skipping URLhaus feed")
        return []

    url = f"{URLHAUS_API_URL}urls/recent/"
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        logger.error("URLhaus request failed: %s", e)
        return []

    iocs: List[IOC] = []
    seen: set = set()

    for entry in (data.get("urls") or []):
        value = entry.get("url", "").strip()
        if not value or value in seen:
            continue
        seen.add(value)

        date_added = entry.get("date_added", "")
        first_seen = _parse_timestamp(date_added) if date_added else datetime.now()

        # URLhaus threat types
        threat = entry.get("threat", "") or ""
        url_status = entry.get("url_status", "")

        # Confidence based on status
        if url_status == "online":
            confidence = 90.0
        elif url_status == "offline":
            confidence = 55.0
        else:
            confidence = 70.0

        severity = _map_severity(threat, confidence)

        ioc = IOC(
            value=value,
            indicator_type=IndicatorType.URL,
            initial_confidence=round(confidence, 2),
            current_confidence=round(confidence, 2),
            first_seen=first_seen,
            last_seen=first_seen,
            observations=[first_seen],
            is_stale=False,
            source="urlhaus",
            severity=severity,
            source_reliability=0.82,
        )
        iocs.append(ioc)

        if len(iocs) >= limit:
            break

    logger.info("URLhaus feed: loaded %d IOCs", len(iocs))
    return iocs


# ═══════════════════════════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

FEED_FUNCTIONS = {
    "otx":       load_otx_feed,
    "threatfox": load_threatfox_feed,
    "urlhaus":   load_urlhaus_feed,
}


def get_feed_status() -> Dict[str, dict]:
    """Return configuration status for each feed (key configured? yes/no)."""
    return {
        "otx": {
            "name": "AlienVault OTX",
            "configured": bool(OTX_API_KEY),
            "icon": "🛰️",
        },
        "threatfox": {
            "name": "ThreatFox",
            "configured": bool(ABUSECH_AUTH_KEY),
            "icon": "🌐",
        },
        "urlhaus": {
            "name": "URLhaus",
            "configured": bool(ABUSECH_AUTH_KEY),
            "icon": "🔗",
        },
    }


def load_live_feed(
    sources: Optional[List[str]] = None,
    limit: int = 50,
    days: int = 7,
) -> List[IOC]:
    """Load IOCs from one or more live feeds, deduplicated.

    Args:
        sources: list of feed names ("otx", "threatfox", "urlhaus").
                 None → all configured feeds.
        limit:   max IOCs per source.
        days:    how many days back to query (supported by OTX & ThreatFox).

    Returns:
        Deduplicated list of IOC objects from all requested sources.
    """
    if sources is None:
        # Use all feeds that have keys configured
        status = get_feed_status()
        sources = [k for k, v in status.items() if v["configured"]]

    if not sources:
        logger.warning("No live feeds configured — returning empty list")
        return []

    all_iocs: List[IOC] = []
    seen_values: set = set()

    for src in sources:
        fn = FEED_FUNCTIONS.get(src)
        if fn is None:
            logger.warning("Unknown feed source: %s", src)
            continue

        # Pass appropriate kwargs
        if src == "otx":
            result = fn(limit=limit, days=days)
        elif src == "threatfox":
            result = fn(days=min(days, 7), limit=limit)
        elif src == "urlhaus":
            result = fn(limit=limit)
        else:
            result = fn(limit=limit)

        for ioc in result:
            if ioc.value not in seen_values:
                seen_values.add(ioc.value)
                all_iocs.append(ioc)

    logger.info("Live feed total: %d IOCs from %s", len(all_iocs), sources)
    return all_iocs
