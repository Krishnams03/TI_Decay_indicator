"""
Configuration for the Adaptive Time-Decay Threat Indicator Scoring Engine.
All tunable parameters live here for easy experimentation.
"""

# ── Decay constants (λ) per indicator type ───────────────────────────────────
# Higher λ  →  faster confidence drop
DECAY_CONSTANTS = {
    "IP":        0.15,   # IPs rotate fast   → aggressive decay
    "DOMAIN":    0.08,   # Domains persist    → moderate decay
    "URL":       0.12,   # URLs shift often   → medium-fast decay
    "FILE_HASH": 0.03,   # Hashes stay valid  → slow decay
    "EMAIL":     0.10,   # Email addresses    → moderate-fast decay
}

# ── Default initial confidence (0–100 scale) ─────────────────────────────────
DEFAULT_INITIAL_CONFIDENCE = 85.0

# ── Adaptive freshness boost (α) applied on re-observation ───────────────────
REINFORCEMENT_BOOST = 15.0        # added to current score on re-sight
MAX_CONFIDENCE      = 100.0       # cap after boost

# ── Threshold settings ───────────────────────────────────────────────────────
STALE_THRESHOLD   = 20.0          # below this → flagged stale
ARCHIVE_THRESHOLD = 5.0           # below this → candidate for archival

# ── File paths ───────────────────────────────────────────────────────────────
import os
_BASE = os.path.dirname(os.path.abspath(__file__))

SAMPLE_FEED_PATH  = os.path.join(_BASE, "data", "sample_iocs.json")
IOC_DATABASE_PATH = os.path.join(_BASE, "data", "ioc_database.json")
OUTPUT_DIR        = os.path.join(_BASE, "output")
