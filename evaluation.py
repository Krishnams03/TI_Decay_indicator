"""
Evaluation module — compute classification metrics for static vs decay scoring.

Enhanced with:
  • Multi-threshold sweep for optimal operating point
  • Adaptive-boost evaluation scenario
  • Confusion matrix breakdown
  • FPR reduction percentage calculation

Metrics computed:
  • Precision          — of IOCs flagged active, how many truly are
  • Recall (TPR)       — of truly active IOCs, how many were flagged active
  • F1 Score           — harmonic mean of precision and recall
  • False Positive Rate — of truly retired IOCs, how many incorrectly flagged active
  • Accuracy           — overall correct classifications
  • AUC-ROC            — area under the ROC curve (threshold sweep)
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from config import STALE_THRESHOLD, OUTPUT_DIR

# ── Colours ──────────────────────────────────────────────────────────────────
BACKGROUND = "#1a1a2e"
CARD_BG    = "#16213e"
TEXT_COLOR  = "#e0e0e0"
GRID_COLOR  = "#2a2a4a"
STATIC_CLR = "#e74c3c"
DECAY_CLR  = "#2ecc71"
WEIGHTED_CLR = "#3498db"
ADAPTIVE_CLR = "#f59e0b"


def _classify(scores: List[float], threshold: float) -> List[bool]:
    """Return True (predicted active) when score >= threshold."""
    return [s >= threshold for s in scores]


def compute_metrics(
    scores: List[float],
    ground_truth: List[bool],
    threshold: float = STALE_THRESHOLD,
) -> Dict[str, float]:
    """Compute precision, recall, F1, FPR, accuracy for the given scores."""
    predictions = _classify(scores, threshold)

    tp = fp = tn = fn = 0
    for pred, truth in zip(predictions, ground_truth):
        if pred and truth:
            tp += 1
        elif pred and not truth:
            fp += 1
        elif not pred and not truth:
            tn += 1
        else:
            fn += 1

    precision  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall     = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1         = (2 * precision * recall / (precision + recall)
                  if (precision + recall) > 0 else 0.0)
    fpr        = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy   = (tp + tn) / len(ground_truth) if ground_truth else 0.0

    return {
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "fpr":       round(fpr, 4),
        "accuracy":  round(accuracy, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def compute_auc_roc(
    scores: List[float],
    ground_truth: List[bool],
    steps: int = 200,
) -> Tuple[List[float], List[float], float]:
    """Sweep thresholds and return (fpr_list, tpr_list, auc)."""
    thresholds = [i * 100.0 / steps for i in range(steps + 1)]
    fpr_list, tpr_list = [], []

    for t in thresholds:
        m = compute_metrics(scores, ground_truth, threshold=t)
        fpr_list.append(m["fpr"])
        tpr_list.append(m["recall"])

    # Trapezoidal AUC
    auc = 0.0
    for i in range(1, len(fpr_list)):
        dx = fpr_list[i] - fpr_list[i - 1]
        auc += (tpr_list[i] + tpr_list[i - 1]) / 2 * dx
    auc = abs(auc)

    return fpr_list, tpr_list, round(auc, 4)


def find_optimal_threshold(
    scores: List[float],
    ground_truth: List[bool],
    steps: int = 200,
) -> Tuple[float, Dict[str, float]]:
    """Find the threshold that maximises F1 score."""
    best_t, best_f1, best_metrics = 0.0, -1.0, {}
    for i in range(steps + 1):
        t = i * 100.0 / steps
        m = compute_metrics(scores, ground_truth, threshold=t)
        if m["f1"] > best_f1:
            best_f1 = m["f1"]
            best_t = t
            best_metrics = m
    return round(best_t, 2), best_metrics


def full_evaluation(
    static_scores: List[float],
    decay_scores: List[float],
    weighted_scores: List[float],
    ground_truth: List[bool],
    threshold: float = STALE_THRESHOLD,
) -> Dict[str, Dict]:
    """Run full evaluation for all three scoring methods."""
    results = {
        "static":   compute_metrics(static_scores, ground_truth, threshold),
        "decay":    compute_metrics(decay_scores, ground_truth, threshold),
        "weighted": compute_metrics(weighted_scores, ground_truth, threshold),
    }

    # Add optimal threshold analysis
    for name, scores in [("static", static_scores), ("decay", decay_scores),
                         ("weighted", weighted_scores)]:
        opt_t, opt_m = find_optimal_threshold(scores, ground_truth)
        results[name]["optimal_threshold"] = opt_t
        results[name]["optimal_f1"] = opt_m["f1"]
        results[name]["optimal_precision"] = opt_m["precision"]
        results[name]["optimal_recall"] = opt_m["recall"]
        results[name]["optimal_fpr"] = opt_m["fpr"]
        results[name]["optimal_accuracy"] = opt_m["accuracy"]

    return results


def threshold_sweep(
    static_scores: List[float],
    decay_scores: List[float],
    weighted_scores: List[float],
    ground_truth: List[bool],
    thresholds: List[float] | None = None,
) -> List[Dict]:
    """Evaluate at multiple thresholds — ideal for paper tables."""
    if thresholds is None:
        thresholds = [10, 15, 20, 25, 30, 40, 50]

    rows = []
    for t in thresholds:
        s = compute_metrics(static_scores, ground_truth, t)
        d = compute_metrics(decay_scores, ground_truth, t)
        w = compute_metrics(weighted_scores, ground_truth, t)
        rows.append({
            "threshold": t,
            "static":   s,
            "decay":    d,
            "weighted": w,
        })
    return rows


# ── Visualizations ──────────────────────────────────────────────────────────

def plot_roc_curves(
    static_scores: List[float],
    decay_scores: List[float],
    weighted_scores: List[float],
    ground_truth: List[bool],
    save: bool = True,
) -> str | None:
    """ROC curves for static, decay, and weighted scoring."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    fig, ax = plt.subplots(figsize=(8, 8))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    for scores, label, color in [
        (static_scores,   "Static",   STATIC_CLR),
        (decay_scores,    "Decay",    DECAY_CLR),
        (weighted_scores, "Weighted", WEIGHTED_CLR),
    ]:
        fpr_l, tpr_l, auc_val = compute_auc_roc(scores, ground_truth)
        ax.plot(fpr_l, tpr_l, color=color, linewidth=2.2,
                label=f"{label}  (AUC = {auc_val:.3f})")

    ax.plot([0, 1], [0, 1], "--", color="#555", linewidth=1, alpha=0.6,
            label="Random (AUC = 0.500)")

    ax.set_xlabel("False Positive Rate", fontsize=11, fontweight="bold", color=TEXT_COLOR)
    ax.set_ylabel("True Positive Rate", fontsize=11, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("ROC Curves — Static vs Decay vs Weighted",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.tick_params(colors=TEXT_COLOR)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, color=GRID_COLOR, linewidth=0.4, alpha=0.6)
    ax.legend(facecolor=CARD_BG, edgecolor=GRID_COLOR,
              labelcolor=TEXT_COLOR, fontsize=10, loc="lower right")

    path = os.path.join(OUTPUT_DIR, "roc_curves.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


def plot_metrics_comparison(
    results: Dict[str, Dict],
    save: bool = True,
) -> str | None:
    """Grouped bar chart comparing metrics across scoring methods."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    metrics = ["precision", "recall", "f1", "accuracy"]
    labels  = ["Precision", "Recall", "F1 Score", "Accuracy"]

    static_vals   = [results["static"][m] for m in metrics]
    decay_vals    = [results["decay"][m] for m in metrics]
    weighted_vals = [results["weighted"][m] for m in metrics]

    x = range(len(metrics))
    w = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    ax.bar([i - w for i in x], static_vals,   w, label="Static",   color=STATIC_CLR, alpha=0.85)
    ax.bar(list(x),            decay_vals,    w, label="Decay",    color=DECAY_CLR, alpha=0.85)
    ax.bar([i + w for i in x], weighted_vals, w, label="Weighted", color=WEIGHTED_CLR, alpha=0.85)

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=11, color=TEXT_COLOR)
    ax.set_ylabel("Score", fontsize=11, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("Evaluation Metrics — Static vs Decay vs Weighted",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.set_ylim(0, 1.1)
    ax.tick_params(colors=TEXT_COLOR)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, axis="y", color=GRID_COLOR, linewidth=0.4, alpha=0.6)
    ax.legend(facecolor=CARD_BG, edgecolor=GRID_COLOR,
              labelcolor=TEXT_COLOR, fontsize=10)

    # Value labels on bars
    for bars in ax.containers:
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.02,
                        f"{h:.2f}", ha="center", fontsize=8, color=TEXT_COLOR)

    path = os.path.join(OUTPUT_DIR, "metrics_comparison.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


def plot_fpr_comparison(results: Dict[str, Dict], save: bool = True) -> str | None:
    """Bar chart specifically highlighting False Positive Rate reduction."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    methods = ["Static", "Decay", "Weighted"]
    fpr_vals = [results["static"]["fpr"], results["decay"]["fpr"], results["weighted"]["fpr"]]
    colors = [STATIC_CLR, DECAY_CLR, WEIGHTED_CLR]

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    bars = ax.bar(methods, fpr_vals, color=colors, width=0.5, alpha=0.85, edgecolor="none")

    for bar, val in zip(bars, fpr_vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{val:.3f}", ha="center", fontsize=12, fontweight="bold", color=TEXT_COLOR)

    ax.set_ylabel("False Positive Rate", fontsize=12, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("False Positive Rate Comparison",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.set_ylim(0, max(fpr_vals) * 1.4 + 0.05)
    ax.tick_params(colors=TEXT_COLOR, labelsize=11)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, axis="y", color=GRID_COLOR, linewidth=0.4, alpha=0.6)

    path = os.path.join(OUTPUT_DIR, "fpr_comparison.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


def plot_f1_vs_threshold(
    static_scores: List[float],
    decay_scores: List[float],
    weighted_scores: List[float],
    ground_truth: List[bool],
    save: bool = True,
) -> str | None:
    """Line chart showing F1 score across different thresholds — helps
    identify the optimal operating point for each method."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    thresholds = [i for i in range(0, 101, 2)]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    for scores, label, color in [
        (static_scores,   "Static",   STATIC_CLR),
        (decay_scores,    "Decay",    DECAY_CLR),
        (weighted_scores, "Weighted", WEIGHTED_CLR),
    ]:
        f1_vals = []
        best_t, best_f1 = 0, 0
        for t in thresholds:
            m = compute_metrics(scores, ground_truth, threshold=t)
            f1_vals.append(m["f1"])
            if m["f1"] > best_f1:
                best_f1 = m["f1"]
                best_t = t

        ax.plot(thresholds, f1_vals, color=color, linewidth=2.2, label=f"{label}")
        # Mark optimal point
        ax.plot(best_t, best_f1, "o", color=color, markersize=8, zorder=5)
        ax.annotate(f"  Best: {best_f1:.2f}\n  @t={best_t}",
                    xy=(best_t, best_f1), fontsize=8, color=color, fontweight="bold")

    ax.set_xlabel("Threshold", fontsize=11, fontweight="bold", color=TEXT_COLOR)
    ax.set_ylabel("F1 Score", fontsize=11, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("F1 Score vs Threshold — Optimal Operating Points",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.set_ylim(0, 1.05)
    ax.tick_params(colors=TEXT_COLOR)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, color=GRID_COLOR, linewidth=0.4, alpha=0.6)
    ax.legend(facecolor=CARD_BG, edgecolor=GRID_COLOR,
              labelcolor=TEXT_COLOR, fontsize=10)

    path = os.path.join(OUTPUT_DIR, "f1_vs_threshold.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None
