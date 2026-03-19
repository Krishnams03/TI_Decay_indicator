"""
Comparison module — Static scoring vs Time-Decay scoring.

Static scoring keeps every IOC at its original confidence forever.
Decay scoring applies our exponential model.  This module computes both
and returns structured comparison data for the article and web UI.
"""

from __future__ import annotations

import copy
import math
import os
from datetime import datetime
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from models import IOC
from decay_engine import apply_decay, calculate_weighted_score, check_stale
from config import DECAY_CONSTANTS, STALE_THRESHOLD, OUTPUT_DIR


# ── Colour constants ─────────────────────────────────────────────────────────
BACKGROUND = "#1a1a2e"
CARD_BG    = "#16213e"
TEXT_COLOR  = "#e0e0e0"
GRID_COLOR  = "#2a2a4a"
STATIC_CLR = "#e74c3c"
DECAY_CLR  = "#2ecc71"


def static_scoring(iocs: List[IOC]) -> List[IOC]:
    """Return copies of IOCs with confidence frozen at initial value."""
    result = []
    for ioc in iocs:
        clone = copy.deepcopy(ioc)
        clone.current_confidence = clone.initial_confidence
        clone.is_stale = False
        clone.weighted_score = clone.initial_confidence
        result.append(clone)
    return result


def decay_scoring(iocs: List[IOC], current_time: datetime) -> List[IOC]:
    """Return copies of IOCs with time-decay applied."""
    result = []
    for ioc in iocs:
        clone = copy.deepcopy(ioc)
        apply_decay(clone, current_time)
        calculate_weighted_score(clone)
        check_stale(clone)
        result.append(clone)
    return result


def compare(
    iocs: List[IOC],
    current_time: datetime,
    threshold: float = STALE_THRESHOLD,
) -> List[Dict]:
    """Build a comparison table: one row per IOC with both scoring methods.

    Each row dict:
      value, type, severity, ground_truth,
      static_score, static_flag (active/stale),
      decay_score, decay_flag,
      weighted_score
    """
    static_list = static_scoring(iocs)
    decay_list  = decay_scoring(iocs, current_time)

    rows = []
    for s_ioc, d_ioc in zip(static_list, decay_list):
        rows.append({
            "value":          s_ioc.value,
            "type":           s_ioc.indicator_type.value,
            "severity":       s_ioc.severity.value,
            "source":         s_ioc.source,
            "ground_truth":   s_ioc.ground_truth_active,
            "days_old":       round((current_time - s_ioc.first_seen).total_seconds() / 86400, 1),
            "static_score":   round(s_ioc.current_confidence, 2),
            "static_flag":    "active" if s_ioc.current_confidence >= threshold else "stale",
            "decay_score":    round(d_ioc.current_confidence, 2),
            "decay_flag":     "active" if d_ioc.current_confidence >= threshold else "stale",
            "weighted_score": round(d_ioc.weighted_score, 2),
        })
    return rows


def generate_comparison_chart(
    rows: List[Dict],
    max_items: int = 30,
    save: bool = True,
) -> str | None:
    """Grouped horizontal bar chart: static vs decay confidence (top N IOCs)."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    subset = rows[:max_items]

    labels  = [f"{r['type']}: {r['value'][:25]}" for r in subset]
    static  = [r["static_score"] for r in subset]
    decay   = [r["decay_score"] for r in subset]

    y_pos = range(len(labels))
    bar_h = 0.35

    fig, ax = plt.subplots(figsize=(12, max(5, len(labels) * 0.5)))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    ax.barh([y - bar_h / 2 for y in y_pos], static, bar_h,
            label="Static Score", color=STATIC_CLR, alpha=0.85)
    ax.barh([y + bar_h / 2 for y in y_pos], decay, bar_h,
            label="Decay Score", color=DECAY_CLR, alpha=0.85)

    ax.axvline(x=STALE_THRESHOLD, color="#ff4757", linestyle="--",
               linewidth=1.2, alpha=0.8, label=f"Stale ({STALE_THRESHOLD})")

    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Confidence Score", fontsize=11, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("Static vs Decay Scoring Comparison",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.set_xlim(0, 105)
    ax.tick_params(colors=TEXT_COLOR, labelsize=8)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, axis="x", color=GRID_COLOR, linewidth=0.4, alpha=0.6)
    ax.legend(facecolor=CARD_BG, edgecolor=GRID_COLOR,
              labelcolor=TEXT_COLOR, fontsize=9)
    ax.invert_yaxis()

    path = os.path.join(OUTPUT_DIR, "static_vs_decay.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None
