"""
Feed Loader — reads a sample threat-feed JSON and normalizes it into IOC objects.

╔══════════════════════════════════════════════════════════════════════╗
║  FEED SOURCE STRATEGY                                              ║
║                                                                    ║
║  This project ships with a LOCAL sample feed file:                 ║
║      data/sample_iocs.json                                         ║
║                                                                    ║
║  The file simulates what a real feed would provide — each entry    ║
║  contains the indicator value, its type, initial confidence, and   ║
║  a first-seen timestamp.                                           ║
║                                                                    ║
║  In a production environment this module would be extended to      ║
║  pull from live feeds such as:                                     ║
║    • MISP  (Malware Information Sharing Platform)                  ║
║    • AlienVault OTX  (Open Threat Exchange REST API)               ║
║    • AbuseIPDB  (IP reputation database)                           ║
║    • VirusTotal  (file/URL/domain scanning)                        ║
║    • STIX/TAXII servers  (structured threat sharing)               ║
║    • CSV / STIX2 flat-file exports from any TI vendor              ║
║                                                                    ║
║  The design keeps feed parsing separate from the decay engine so   ║
║  swapping in a real feed only requires changing this module.       ║
╚══════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import List

from models import IOC, IndicatorType
from config import DEFAULT_INITIAL_CONFIDENCE


def _normalise_type(raw: str) -> IndicatorType:
    """Map free-form type strings to the IndicatorType enum."""
    mapping = {
        "ip":        IndicatorType.IP,
        "ip_address": IndicatorType.IP,
        "domain":    IndicatorType.DOMAIN,
        "url":       IndicatorType.URL,
        "hash":      IndicatorType.FILE_HASH,
        "file_hash": IndicatorType.FILE_HASH,
        "md5":       IndicatorType.FILE_HASH,
        "sha256":    IndicatorType.FILE_HASH,
        "email":     IndicatorType.EMAIL,
    }
    return mapping.get(raw.strip().lower(), IndicatorType.IP)


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
