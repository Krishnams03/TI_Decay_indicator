"""
Visualizer — generates matplotlib charts for confidence analysis.

Produces three charts:
  1. Theoretical decay curves for every indicator type over 60 days
  2. Bar chart of current IOC confidence values in the store
  3. Adaptive scenario: an IP decaying then getting a re-observation boost
"""

from __future__ import annotations

import math
import os
from datetime import datetime, timedelta
from typing import Optional

import matplotlib
matplotlib.use("Agg")                       # headless backend
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

from config import (
    DECAY_CONSTANTS,
    DEFAULT_INITIAL_CONFIDENCE,
    REINFORCEMENT_BOOST,
    MAX_CONFIDENCE,
    STALE_THRESHOLD,
    OUTPUT_DIR,
)
from ioc_store import IOCStore


# ── Colour palette ───────────────────────────────────────────────────────────
COLORS = {
    "IP":        "#e74c3c",
    "DOMAIN":    "#3498db",
    "URL":       "#e67e22",
    "FILE_HASH": "#2ecc71",
    "EMAIL":     "#9b59b6",
}

BACKGROUND    = "#1a1a2e"
CARD_BG       = "#16213e"
TEXT_COLOR     = "#e0e0e0"
GRID_COLOR     = "#2a2a4a"
ACCENT         = "#00d9ff"


def _ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _apply_dark_style(ax: plt.Axes, fig: plt.Figure) -> None:
    """Apply a sleek dark theme to a single axes."""
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)
    ax.tick_params(colors=TEXT_COLOR, labelsize=9)
    ax.xaxis.label.set_color(TEXT_COLOR)
    ax.yaxis.label.set_color(TEXT_COLOR)
    ax.title.set_color(TEXT_COLOR)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, color=GRID_COLOR, linewidth=0.4, alpha=0.6)


# ═══════════════════════════════════════════════════════════════════════
# Chart 1 — Theoretical decay curves
# ═══════════════════════════════════════════════════════════════════════

def plot_decay_curves(days: int = 60, save: bool = True) -> Optional[str]:
    """Plot C(t) = C₀·e^(-λt) for each indicator type."""
    _ensure_output_dir()
    fig, ax = plt.subplots(figsize=(10, 6))
    _apply_dark_style(ax, fig)

    t_range = range(days + 1)
    c0 = DEFAULT_INITIAL_CONFIDENCE

    for itype, lam in DECAY_CONSTANTS.items():
        scores = [c0 * math.exp(-lam * t) for t in t_range]
        ax.plot(t_range, scores, label=f"{itype}  (λ={lam})",
                color=COLORS[itype], linewidth=2.2)

    # Stale threshold line
    ax.axhline(y=STALE_THRESHOLD, color="#ff4757", linestyle="--",
               linewidth=1.2, alpha=0.8, label=f"Stale threshold ({STALE_THRESHOLD})")

    ax.set_xlabel("Days since last observation", fontsize=11, fontweight="bold")
    ax.set_ylabel("Confidence Score", fontsize=11, fontweight="bold")
    ax.set_title("Exponential Decay Curves by Indicator Type",
                 fontsize=14, fontweight="bold", pad=12)
    ax.set_ylim(0, 100)
    ax.legend(facecolor=CARD_BG, edgecolor=GRID_COLOR,
              labelcolor=TEXT_COLOR, fontsize=9, loc="upper right")

    path = os.path.join(OUTPUT_DIR, "decay_curves.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


# ═══════════════════════════════════════════════════════════════════════
# Chart 2 — Current confidence bar chart
# ═══════════════════════════════════════════════════════════════════════

def plot_ioc_confidence(store: IOCStore, save: bool = True) -> Optional[str]:
    """Horizontal bar chart of current confidence for every IOC in *store*."""
    _ensure_output_dir()
    iocs = sorted(store.get_all(), key=lambda i: i.current_confidence)

    labels = [f"{i.indicator_type.value}: {i.value[:28]}" for i in iocs]
    scores = [i.current_confidence for i in iocs]
    bar_colors = [COLORS.get(i.indicator_type.value, ACCENT) for i in iocs]

    fig, ax = plt.subplots(figsize=(10, max(4, len(iocs) * 0.55)))
    _apply_dark_style(ax, fig)

    bars = ax.barh(labels, scores, color=bar_colors, edgecolor="none", height=0.65)

    # Stale threshold line
    ax.axvline(x=STALE_THRESHOLD, color="#ff4757", linestyle="--",
               linewidth=1.2, alpha=0.8, label=f"Stale ({STALE_THRESHOLD})")

    for bar, score in zip(bars, scores):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                f"{score:.1f}", va="center", color=TEXT_COLOR, fontsize=8)

    ax.set_xlabel("Confidence Score", fontsize=11, fontweight="bold")
    ax.set_title("Current IOC Confidence Levels",
                 fontsize=14, fontweight="bold", pad=12)
    ax.set_xlim(0, 105)
    ax.legend(facecolor=CARD_BG, edgecolor=GRID_COLOR,
              labelcolor=TEXT_COLOR, fontsize=9)

    path = os.path.join(OUTPUT_DIR, "ioc_confidence.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


# ═══════════════════════════════════════════════════════════════════════
# Chart 3 — Adaptive scenario (decay + boost)
# ═══════════════════════════════════════════════════════════════════════

def plot_adaptive_scenario(save: bool = True) -> Optional[str]:
    """Show a sample IP decaying for 30 days with a boost at day 15."""
    _ensure_output_dir()
    c0 = 90.0
    lam = DECAY_CONSTANTS["IP"]
    boost_day = 15
    alpha = REINFORCEMENT_BOOST
    total_days = 40

    days, scores = [], []
    current = c0
    for d in range(total_days + 1):
        if d <= boost_day:
            current = c0 * math.exp(-lam * d)
        elif d == boost_day + 1:
            # boost happens
            boosted = c0 * math.exp(-lam * boost_day) + alpha
            current = min(boosted, MAX_CONFIDENCE)
            # now decay from boosted value
            c0_new = current
            current = c0_new  # day 0 after boost
        else:
            elapsed_after_boost = d - (boost_day + 1)
            current = c0_new * math.exp(-lam * elapsed_after_boost)
        days.append(d)
        scores.append(current)

    fig, ax = plt.subplots(figsize=(10, 6))
    _apply_dark_style(ax, fig)

    ax.plot(days, scores, color=COLORS["IP"], linewidth=2.4,
            label="IP 203.0.113.50")

    # Mark boost point
    ax.annotate("Re-observed →\nBoost +α",
                xy=(boost_day + 1, scores[boost_day + 1]),
                xytext=(boost_day + 5, scores[boost_day + 1] + 12),
                fontsize=9, color=ACCENT, fontweight="bold",
                arrowprops=dict(arrowstyle="->", color=ACCENT, lw=1.5))

    ax.axhline(y=STALE_THRESHOLD, color="#ff4757", linestyle="--",
               linewidth=1.2, alpha=0.8, label=f"Stale threshold ({STALE_THRESHOLD})")

    ax.set_xlabel("Days", fontsize=11, fontweight="bold")
    ax.set_ylabel("Confidence Score", fontsize=11, fontweight="bold")
    ax.set_title("Adaptive Decay + Re-observation Boost (IP Address)",
                 fontsize=14, fontweight="bold", pad=12)
    ax.set_ylim(0, 105)
    ax.legend(facecolor=CARD_BG, edgecolor=GRID_COLOR,
              labelcolor=TEXT_COLOR, fontsize=9)

    path = os.path.join(OUTPUT_DIR, "adaptive_scenario.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None
