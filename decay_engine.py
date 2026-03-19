"""
Core decay engine — multiple decay models, adaptive freshness boost,
and multi-factor weighted scoring.

Decay Models
────────────
  Exponential: C(t) = C₀ × e^(−λt)
  Linear:      C(t) = C₀ × max(0, 1 − λt/k)      where k normalizes to 0 at ~60 days
  Sigmoid:     C(t) = C₀ × 1/(1 + e^(λ(t − t_half)))
  Power-law:   C(t) = C₀ × (1 + t)^(−λ)

  Weighted score (novel):
    W(t) = C(t) × severity_multiplier × source_reliability

  Adaptive boost on re-observation:
    C_new = min(C(t) + α, MAX_CONFIDENCE)
"""

from __future__ import annotations

import math
from datetime import datetime

from models import IOC, SEVERITY_MULTIPLIERS
from config import (
    DECAY_CONSTANTS,
    REINFORCEMENT_BOOST,
    MAX_CONFIDENCE,
    STALE_THRESHOLD,
    ARCHIVE_THRESHOLD,
)

# Available decay models
DECAY_MODELS = ["exponential", "linear", "sigmoid", "power_law"]


# ── Pure math — multiple decay functions ─────────────────────────────────────

def calculate_decay(c0: float, lam: float, t_days: float) -> float:
    """Return decayed confidence: C₀ × e^(−λt) [exponential]."""
    return c0 * math.exp(-lam * t_days)


def calculate_decay_linear(c0: float, lam: float, t_days: float) -> float:
    """Linear decay: C₀ × max(0, 1 − λt/k).  k=10 normalizes rate."""
    k = 10.0
    return c0 * max(0.0, 1.0 - lam * t_days / k)


def calculate_decay_sigmoid(c0: float, lam: float, t_days: float,
                            t_half: float = 15.0) -> float:
    """Sigmoid decay: drops sharply around t_half days."""
    exponent = lam * (t_days - t_half)
    exponent = min(exponent, 500)   # prevent overflow
    return c0 / (1.0 + math.exp(exponent))


def calculate_decay_power_law(c0: float, lam: float, t_days: float) -> float:
    """Power-law decay: C₀ × (1 + t)^(−λ).  Slower than exponential."""
    return c0 * math.pow(1.0 + t_days, -lam)


def _get_decay_fn(model: str):
    """Return the decay function for the given model name."""
    return {
        "exponential": calculate_decay,
        "linear":      calculate_decay_linear,
        "sigmoid":     calculate_decay_sigmoid,
        "power_law":   calculate_decay_power_law,
    }[model]


# ── IOC-level operations ────────────────────────────────────────────────────

def apply_decay(ioc: IOC, current_time: datetime) -> float:
    """Compute and set decayed confidence for *ioc* as of *current_time*."""
    lam = DECAY_CONSTANTS.get(ioc.indicator_type.value, 0.10)
    elapsed = (current_time - ioc.last_seen).total_seconds() / 86_400  # days
    elapsed = max(elapsed, 0)

    new_confidence = calculate_decay(ioc.initial_confidence, lam, elapsed)
    ioc.current_confidence = round(new_confidence, 4)
    return ioc.current_confidence


def apply_decay_with_model(ioc: IOC, current_time: datetime,
                           model: str = "exponential") -> float:
    """Apply decay using the specified model (exponential/linear/sigmoid/power_law)."""
    lam = DECAY_CONSTANTS.get(ioc.indicator_type.value, 0.10)
    elapsed = (current_time - ioc.last_seen).total_seconds() / 86_400
    elapsed = max(elapsed, 0)

    decay_fn = _get_decay_fn(model)
    new_confidence = decay_fn(ioc.initial_confidence, lam, elapsed)
    ioc.current_confidence = round(max(new_confidence, 0.0), 4)
    return ioc.current_confidence


def calculate_weighted_score(ioc: IOC) -> float:
    """Novel multi-factor scoring: decay × severity × source reliability.

    This combines three independent quality signals into a single
    actionable score, providing richer prioritization than decay alone.
    """
    sev_mult = SEVERITY_MULTIPLIERS.get(ioc.severity, 0.7)
    ioc.weighted_score = round(
        ioc.current_confidence * sev_mult * ioc.source_reliability, 4
    )
    return ioc.weighted_score


def apply_boost(ioc: IOC, observation_time: datetime,
                alpha: float = REINFORCEMENT_BOOST) -> float:
    """Boost confidence on re-observation (adaptive freshness)."""
    ioc.current_confidence = min(ioc.current_confidence + alpha, MAX_CONFIDENCE)
    ioc.last_seen = observation_time
    ioc.observations.append(observation_time)
    ioc.is_stale = False
    return ioc.current_confidence


def check_stale(ioc: IOC, threshold: float = STALE_THRESHOLD) -> bool:
    """Flag the IOC as stale if confidence is below *threshold*."""
    ioc.is_stale = ioc.current_confidence < threshold
    return ioc.is_stale


def should_archive(ioc: IOC, threshold: float = ARCHIVE_THRESHOLD) -> bool:
    """Return True if the IOC's confidence has dropped below the archive level."""
    return ioc.current_confidence < threshold
