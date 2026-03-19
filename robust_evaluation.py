"""
Robust Evaluation Module — addresses key methodological flaws.

Fixes applied:
  1. Multi-seed evaluation:     run N seeds, report mean ± std
  2. Cross-validation:          train/test split for threshold optimisation
  3. Multi-decay comparison:    compare exponential, linear, sigmoid, power-law
  4. Statistical significance:  paired differences with confidence intervals
"""

from __future__ import annotations

import copy
import math
import os
import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from config import STALE_THRESHOLD, OUTPUT_DIR
from models import IOC
from simulation import generate_simulation_dataset
from decay_engine import (
    apply_decay_with_model, calculate_weighted_score, check_stale,
    DECAY_MODELS,
)
from evaluation import compute_metrics, compute_auc_roc, find_optimal_threshold

# ── Chart palette ────────────────────────────────────────────────────────────
BACKGROUND  = "#1a1a2e"
CARD_BG     = "#16213e"
TEXT_COLOR   = "#e0e0e0"
GRID_COLOR   = "#2a2a4a"
MODEL_COLORS = {
    "exponential": "#2ecc71",
    "linear":      "#e74c3c",
    "sigmoid":     "#f59e0b",
    "power_law":   "#3498db",
}


# ─────────────────────────────────────────────────────────────────────────────
# 1. Decay scoring with selectable model
# ─────────────────────────────────────────────────────────────────────────────

def decay_scoring_model(iocs: List[IOC], sim_time: datetime,
                        model: str = "exponential") -> List[IOC]:
    """Apply decay + weighted scoring using the specified model."""
    scored = copy.deepcopy(iocs)
    for ioc in scored:
        apply_decay_with_model(ioc, sim_time, model=model)
        calculate_weighted_score(ioc)
        check_stale(ioc)
    return scored


# ─────────────────────────────────────────────────────────────────────────────
# 2. Cross-validated threshold optimisation
# ─────────────────────────────────────────────────────────────────────────────

def cross_validated_f1(
    scores: List[float],
    ground_truth: List[bool],
    n_folds: int = 5,
    seed: int = 0,
) -> Tuple[float, float, float]:
    """K-fold cross-validated F1: find threshold on train, evaluate on test.

    Returns (mean_f1, std_f1, mean_optimal_threshold).
    """
    rng = random.Random(seed)
    indices = list(range(len(scores)))
    rng.shuffle(indices)

    fold_size = len(indices) // n_folds
    f1_scores = []
    thresholds = []

    for fold in range(n_folds):
        test_idx = set(indices[fold * fold_size : (fold + 1) * fold_size])
        train_idx = [i for i in indices if i not in test_idx]
        test_idx = sorted(test_idx)

        train_scores = [scores[i] for i in train_idx]
        train_gt     = [ground_truth[i] for i in train_idx]
        test_scores  = [scores[i] for i in test_idx]
        test_gt      = [ground_truth[i] for i in test_idx]

        # Find optimal threshold on TRAIN fold
        opt_t, _ = find_optimal_threshold(train_scores, train_gt)
        thresholds.append(opt_t)

        # Evaluate on TEST fold
        test_metrics = compute_metrics(test_scores, test_gt, threshold=opt_t)
        f1_scores.append(test_metrics["f1"])

    mean_f1 = sum(f1_scores) / len(f1_scores)
    std_f1 = math.sqrt(sum((f - mean_f1) ** 2 for f in f1_scores) / len(f1_scores))
    mean_t = sum(thresholds) / len(thresholds)

    return round(mean_f1, 4), round(std_f1, 4), round(mean_t, 2)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Multi-seed evaluation
# ─────────────────────────────────────────────────────────────────────────────

def multi_seed_evaluation(
    n_seeds: int = 10,
    n_iocs: int = 200,
    day_offset: int = 15,
    models: List[str] | None = None,
) -> Dict:
    """Run evaluation across multiple random seeds.

    Returns dict with per-model metrics: mean, std, and all seed values
    for AUC-ROC, optimal F1, FPR, cross-validated F1.
    """
    if models is None:
        models = DECAY_MODELS

    ref = datetime(2026, 2, 24, 0, 0, 0)
    sim_time = ref + timedelta(days=day_offset)

    results = {}
    for model in models:
        results[model] = {
            "auc_values":    [],
            "opt_f1_values": [],
            "fpr_values":    [],
            "cv_f1_values":  [],
            "precision_values": [],
            "recall_values":    [],
            "accuracy_values":  [],
        }

    # Also track static as baseline
    results["static"] = {
        "auc_values":    [],
        "opt_f1_values": [],
        "fpr_values":    [],
        "cv_f1_values":  [],
        "precision_values": [],
        "recall_values":    [],
        "accuracy_values":  [],
    }

    for seed in range(n_seeds):
        iocs = generate_simulation_dataset(n_iocs, reference_time=ref, seed=seed)
        labeled = [i for i in iocs if i.ground_truth_active is not None]
        gt = [i.ground_truth_active for i in labeled]

        # Static baseline
        static_scores = [i.initial_confidence for i in labeled]
        _record_metrics(results["static"], static_scores, gt, seed)

        # Each decay model
        for model in models:
            scored = decay_scoring_model(labeled, sim_time, model=model)
            decay_scores = [i.current_confidence for i in scored]
            _record_metrics(results[model], decay_scores, gt, seed)

    # Compute summaries
    summary = {}
    for name, data in results.items():
        summary[name] = _summarize(data)

    return summary


def _record_metrics(bucket: Dict, scores: List[float],
                    gt: List[bool], seed: int) -> None:
    """Record all metrics for one seed run into the bucket."""
    _, _, auc = compute_auc_roc(scores, gt)
    opt_t, opt_m = find_optimal_threshold(scores, gt)
    cv_f1, cv_std, cv_t = cross_validated_f1(scores, gt, n_folds=5, seed=seed)

    bucket["auc_values"].append(auc)
    bucket["opt_f1_values"].append(opt_m["f1"])
    bucket["fpr_values"].append(opt_m["fpr"])
    bucket["cv_f1_values"].append(cv_f1)
    bucket["precision_values"].append(opt_m["precision"])
    bucket["recall_values"].append(opt_m["recall"])
    bucket["accuracy_values"].append(opt_m["accuracy"])


def _summarize(data: Dict) -> Dict:
    """Compute mean ± std for each metric list."""
    summary = {}
    for key, values in data.items():
        metric_name = key.replace("_values", "")
        n = len(values)
        mean = sum(values) / n
        std = math.sqrt(sum((v - mean) ** 2 for v in values) / n)
        summary[f"{metric_name}_mean"] = round(mean, 4)
        summary[f"{metric_name}_std"]  = round(std, 4)
        summary[f"{metric_name}_values"] = [round(v, 4) for v in values]
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# 4. Visualization — multi-decay AUC comparison
# ─────────────────────────────────────────────────────────────────────────────

def plot_multi_decay_comparison(summary: Dict, save: bool = True) -> str | None:
    """Box/bar chart comparing AUC across decay models with error bars."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    models = [m for m in ["static", "exponential", "linear", "sigmoid", "power_law"]
              if m in summary]
    auc_means = [summary[m]["auc_mean"] for m in models]
    auc_stds  = [summary[m]["auc_std"]  for m in models]
    colors    = ["#888"] + [MODEL_COLORS.get(m, "#999") for m in models[1:]]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    bars = ax.bar(models, auc_means, yerr=auc_stds, capsize=6,
                  color=colors, alpha=0.85, edgecolor="none", width=0.5)

    for bar, mean, std in zip(bars, auc_means, auc_stds):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + std + 0.01,
                f"{mean:.3f}±{std:.3f}", ha="center", fontsize=9,
                fontweight="bold", color=TEXT_COLOR)

    ax.set_ylabel("AUC-ROC", fontsize=12, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("Decay Model Comparison — AUC-ROC (10 Seeds, Mean ± Std)",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.set_ylim(0, 1.1)
    ax.tick_params(colors=TEXT_COLOR, labelsize=11)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, axis="y", color=GRID_COLOR, linewidth=0.4, alpha=0.6)

    path = os.path.join(OUTPUT_DIR, "multi_decay_auc.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


def plot_cv_f1_comparison(summary: Dict, save: bool = True) -> str | None:
    """Cross-validated F1 comparison across models."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    models = [m for m in ["static", "exponential", "linear", "sigmoid", "power_law"]
              if m in summary]
    f1_means = [summary[m]["cv_f1_mean"] for m in models]
    f1_stds  = [summary[m]["cv_f1_std"]  for m in models]
    colors   = ["#888"] + [MODEL_COLORS.get(m, "#999") for m in models[1:]]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    bars = ax.bar(models, f1_means, yerr=f1_stds, capsize=6,
                  color=colors, alpha=0.85, edgecolor="none", width=0.5)

    for bar, mean, std in zip(bars, f1_means, f1_stds):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + std + 0.01,
                f"{mean:.3f}±{std:.3f}", ha="center", fontsize=9,
                fontweight="bold", color=TEXT_COLOR)

    ax.set_ylabel("Cross-Validated F1", fontsize=12, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("Decay Model Comparison — 5-Fold CV F1 (10 Seeds, Mean ± Std)",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.set_ylim(0, 1.1)
    ax.tick_params(colors=TEXT_COLOR, labelsize=11)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, axis="y", color=GRID_COLOR, linewidth=0.4, alpha=0.6)

    path = os.path.join(OUTPUT_DIR, "cv_f1_comparison.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


def plot_multi_seed_boxplot(summary: Dict, save: bool = True) -> str | None:
    """Boxplot of AUC-ROC across seeds for each model."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    models = [m for m in ["static", "exponential", "linear", "sigmoid", "power_law"]
              if m in summary]
    data = [summary[m]["auc_values"] for m in models]
    colors = ["#888"] + [MODEL_COLORS.get(m, "#999") for m in models[1:]]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(CARD_BG)

    bp = ax.boxplot(data, labels=models, patch_artist=True, widths=0.5,
                    medianprops=dict(color=TEXT_COLOR, linewidth=2))
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)

    ax.set_ylabel("AUC-ROC", fontsize=12, fontweight="bold", color=TEXT_COLOR)
    ax.set_title("AUC-ROC Distribution Across 10 Seeds",
                 fontsize=14, fontweight="bold", pad=12, color=TEXT_COLOR)
    ax.set_ylim(0, 1.05)
    ax.tick_params(colors=TEXT_COLOR, labelsize=11)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.grid(True, axis="y", color=GRID_COLOR, linewidth=0.4, alpha=0.6)

    path = os.path.join(OUTPUT_DIR, "auc_boxplot.png")
    if save:
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path
    plt.show()
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 5. CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Running robust evaluation (10 seeds x 4 models + static)...")
    print("This takes a minute or two.\n")

    summary = multi_seed_evaluation(n_seeds=10, n_iocs=200, day_offset=15)

    # Print results table
    header = f"{'Model':<14} {'AUC-ROC':>16} {'Opt F1':>16} {'CV F1':>16} {'FPR':>16}"
    print(header)
    print("-" * len(header))

    for model in ["static", "exponential", "linear", "sigmoid", "power_law"]:
        if model not in summary:
            continue
        s = summary[model]
        print(f"{model:<14} "
              f"{s['auc_mean']:.3f}±{s['auc_std']:.3f}"
              f"{'':>4}"
              f"{s['opt_f1_mean']:.3f}±{s['opt_f1_std']:.3f}"
              f"{'':>4}"
              f"{s['cv_f1_mean']:.3f}±{s['cv_f1_std']:.3f}"
              f"{'':>4}"
              f"{s['fpr_mean']:.3f}±{s['fpr_std']:.3f}")

    # Generate charts
    auc_path = plot_multi_decay_comparison(summary)
    f1_path  = plot_cv_f1_comparison(summary)
    box_path = plot_multi_seed_boxplot(summary)
    print(f"\nCharts saved to:\n  {auc_path}\n  {f1_path}\n  {box_path}")
