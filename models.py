"""
Data models for threat indicators (IOCs).

Includes severity weighting, source reliability, and optional ground-truth
labels for evaluation against simulation data.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class IndicatorType(Enum):
    """Supported indicator-of-compromise categories."""
    IP        = "IP"
    DOMAIN    = "DOMAIN"
    URL       = "URL"
    FILE_HASH = "FILE_HASH"
    EMAIL     = "EMAIL"


class Severity(Enum):
    """Threat severity level with associated score multiplier."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


# Multiplier applied to the confidence score based on severity
SEVERITY_MULTIPLIERS = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH:     0.85,
    Severity.MEDIUM:   0.70,
    Severity.LOW:      0.50,
}


@dataclass
class IOC:
    """Represents a single Indicator of Compromise with confidence metadata."""

    value:                str
    indicator_type:       IndicatorType
    initial_confidence:   float
    current_confidence:   float
    first_seen:           datetime
    last_seen:            datetime
    observations:         List[datetime] = field(default_factory=list)
    is_stale:             bool = False
    source:               str = "sample_feed"

    # ── Novel fields ─────────────────────────────────────────────────────
    severity:             Severity = Severity.HIGH
    source_reliability:   float = 0.8          # 0.0 – 1.0
    weighted_score:       float = 0.0          # decay × severity × reliability

    # ── Evaluation label (simulation only) ───────────────────────────────
    ground_truth_active:  Optional[bool] = None   # True = still malicious

    # ── Serialization helpers ────────────────────────────────────────────
    def to_dict(self) -> dict:
        d = {
            "value":                self.value,
            "indicator_type":       self.indicator_type.value,
            "initial_confidence":   self.initial_confidence,
            "current_confidence":   round(self.current_confidence, 4),
            "first_seen":           self.first_seen.isoformat(),
            "last_seen":            self.last_seen.isoformat(),
            "observations":         [o.isoformat() for o in self.observations],
            "is_stale":             self.is_stale,
            "source":               self.source,
            "severity":             self.severity.value,
            "source_reliability":   self.source_reliability,
            "weighted_score":       round(self.weighted_score, 4),
        }
        if self.ground_truth_active is not None:
            d["ground_truth_active"] = self.ground_truth_active
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "IOC":
        severity_str = d.get("severity", "high")
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.HIGH

        return cls(
            value=d["value"],
            indicator_type=IndicatorType(d["indicator_type"]),
            initial_confidence=d["initial_confidence"],
            current_confidence=d["current_confidence"],
            first_seen=datetime.fromisoformat(d["first_seen"]),
            last_seen=datetime.fromisoformat(d["last_seen"]),
            observations=[datetime.fromisoformat(o) for o in d.get("observations", [])],
            is_stale=d.get("is_stale", False),
            source=d.get("source", "unknown"),
            severity=severity,
            source_reliability=d.get("source_reliability", 0.8),
            weighted_score=d.get("weighted_score", 0.0),
            ground_truth_active=d.get("ground_truth_active"),
        )

    def __repr__(self) -> str:
        return (
            f"IOC({self.indicator_type.value}: {self.value!r}, "
            f"confidence={self.current_confidence:.2f}, "
            f"weighted={self.weighted_score:.2f}, stale={self.is_stale})"
        )
