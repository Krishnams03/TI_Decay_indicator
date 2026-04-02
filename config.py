"""
Configuration for the Adaptive Time-Decay Threat Indicator Scoring Engine.
All tunable parameters live here for easy experimentation.
"""

import os


def _load_dotenv(dotenv_path: str) -> None:
    """Load simple KEY=VALUE pairs from .env into process environment.

    Existing OS environment variables take precedence.
    """
    if not os.path.exists(dotenv_path):
        return

    with open(dotenv_path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Remove optional surrounding quotes in .env values
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]

            if key:
                os.environ.setdefault(key, value)


_BASE = os.path.dirname(os.path.abspath(__file__))
_load_dotenv(os.path.join(_BASE, ".env"))

# ── Live Feed API Keys ───────────────────────────────────────────────────────
# Set these via environment variables or a .env file
OTX_API_KEY       = os.environ.get("OTX_API_KEY", "")
ABUSECH_AUTH_KEY  = os.environ.get("ABUSECH_AUTH_KEY", "")

# ── Live Feed Endpoints ──────────────────────────────────────────────────────
OTX_API_URL       = "https://otx.alienvault.com/api/v1/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API_URL   = "https://urlhaus-api.abuse.ch/v1/"

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
SAMPLE_FEED_PATH  = os.path.join(_BASE, "data", "sample_iocs.json")
IOC_DATABASE_PATH = os.path.join(_BASE, "data", "ioc_database.json")
OUTPUT_DIR        = os.path.join(_BASE, "output")
