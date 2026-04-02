"""
Flask web application — REST API + dashboard for the Decay Engine.

Endpoints:
  GET  /                      → serve the dashboard
  POST /api/load-feed         → load sample or simulation feed
  POST /api/load-live-feed    → load from live TI sources (OTX, ThreatFox, URLhaus)
  GET  /api/feed-status       → check which live feeds are configured
  POST /api/apply-decay       → apply decay at a given day offset
  POST /api/boost             → re-observe a specific IOC
  GET  /api/comparison        → static vs decay comparison
  GET  /api/evaluation        → full evaluation metrics + chart paths
"""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()   # load .env before config reads os.environ

import base64
import io
import json
import os
import copy
from datetime import datetime, timedelta
from typing import List

from flask import Flask, jsonify, request, render_template, send_from_directory

from config import (
    SAMPLE_FEED_PATH, IOC_DATABASE_PATH, OUTPUT_DIR,
    STALE_THRESHOLD, _BASE,
)
from models import IOC
from ioc_store import IOCStore
from feed_loader import load_sample_feed, load_live_feed, get_feed_status
from decay_engine import apply_decay, apply_boost, check_stale, calculate_weighted_score
from confidence_updater import update_all, get_priority_list
from simulation import generate_simulation_dataset, save_simulation_dataset
from comparison import compare, generate_comparison_chart, static_scoring, decay_scoring
from evaluation import (
    full_evaluation, compute_auc_roc, threshold_sweep,
    plot_roc_curves, plot_metrics_comparison, plot_fpr_comparison,
    plot_f1_vs_threshold,
)


app = Flask(__name__,
            template_folder=os.path.join(_BASE, "templates"),
            static_folder=os.path.join(_BASE, "static"))

# ── In-memory state ──────────────────────────────────────────────────────────
_store = IOCStore(IOC_DATABASE_PATH)
_original_iocs: List[IOC] = []        # snapshot of feed before any decay
_reference_time = datetime.now().replace(microsecond=0)


def _img_to_base64(path: str) -> str:
    """Read an image file and return a base64 data-URI."""
    with open(path, "rb") as f:
        data = base64.b64encode(f.read()).decode()
    return f"data:image/png;base64,{data}"


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/output/<path:filename>")
def serve_output(filename):
    return send_from_directory(OUTPUT_DIR, filename)


# ── API: Load Feed ───────────────────────────────────────────────────────────

@app.route("/api/load-feed", methods=["POST"])
def api_load_feed():
    """Load the sample feed or generate simulation dataset."""
    global _original_iocs, _store, _reference_time

    body = request.get_json(silent=True) or {}
    feed_type = body.get("feed_type", "sample")   # "sample" or "simulation"

    # Re-anchor simulation time each load so live feeds decay correctly.
    load_time = datetime.now().replace(microsecond=0)
    _reference_time = load_time

    if feed_type == "simulation":
        iocs = generate_simulation_dataset(200, reference_time=load_time)
        sim_path = os.path.join(_BASE, "data", "simulation_iocs.json")
        save_simulation_dataset(iocs, sim_path)
    else:
        iocs = load_sample_feed(SAMPLE_FEED_PATH)

    # Use the latest observation in the loaded feed as t=0 for comparisons.
    if iocs:
        _reference_time = max(i.last_seen for i in iocs)

    _original_iocs = copy.deepcopy(iocs)
    _store = IOCStore(IOC_DATABASE_PATH)
    for ioc in iocs:
        _store.add_ioc(ioc)
    _store.save()

    return jsonify({
        "status": "ok",
        "count": len(iocs),
        "feed_type": feed_type,
        "reference_time": _reference_time.isoformat(),
        "iocs": [ioc.to_dict() for ioc in iocs],
    })


# ── API: Load Live Feed ─────────────────────────────────────────────────────

@app.route("/api/load-live-feed", methods=["POST"])
def api_load_live_feed():
    """Load IOCs from one or more live threat intelligence feeds."""
    global _original_iocs, _store

    body = request.get_json(silent=True) or {}
    sources = body.get("sources", None)      # list of feed names, or None for all
    limit   = int(body.get("limit", 50))
    days    = int(body.get("days", 7))

    try:
        iocs = load_live_feed(sources=sources, limit=limit, days=days)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    if not iocs:
        return jsonify({
            "status": "error",
            "message": "No IOCs returned. Check your API keys and network connection.",
        }), 400

    # Use current time as reference for live data
    _original_iocs = copy.deepcopy(iocs)
    _store = IOCStore(IOC_DATABASE_PATH)
    for ioc in iocs:
        _store.add_ioc(ioc)
    _store.save()

    return jsonify({
        "status": "ok",
        "count": len(iocs),
        "feed_type": "live",
        "sources": sources or ["all configured"],
        "iocs": [ioc.to_dict() for ioc in iocs],
    })


# ── API: Feed Status ────────────────────────────────────────────────────────

@app.route("/api/feed-status", methods=["GET"])
def api_feed_status():
    """Return which live feeds have API keys configured."""
    return jsonify(get_feed_status())


# ── API: Apply Decay ────────────────────────────────────────────────────────

@app.route("/api/apply-decay", methods=["POST"])
def api_apply_decay():
    """Apply time-decay at a user-specified day offset."""
    global _store

    body = request.get_json(silent=True) or {}
    day_offset = int(body.get("days", 0))

    # Reload originals so decay is always from first_seen
    _store = IOCStore(IOC_DATABASE_PATH)
    for ioc in copy.deepcopy(_original_iocs):
        _store.add_ioc(ioc)

    sim_time = _reference_time + timedelta(days=day_offset)
    for ioc in _store.get_all():
        apply_decay(ioc, sim_time)
        calculate_weighted_score(ioc)
        check_stale(ioc)

    scored = get_priority_list(_store)
    return jsonify({
        "status": "ok",
        "day_offset": day_offset,
        "sim_time": sim_time.isoformat(),
        "iocs": [ioc.to_dict() for ioc in scored],
    })


# ── API: Boost ───────────────────────────────────────────────────────────────

@app.route("/api/boost", methods=["POST"])
def api_boost():
    body = request.get_json(silent=True) or {}
    value = body.get("value", "")
    ioc = _store.get_ioc(value)
    if ioc is None:
        return jsonify({"status": "error", "message": "IOC not found"}), 404
    apply_boost(ioc, datetime.now())
    calculate_weighted_score(ioc)
    return jsonify({"status": "ok", "ioc": ioc.to_dict()})


# ── API: Comparison ──────────────────────────────────────────────────────────

@app.route("/api/comparison", methods=["GET"])
def api_comparison():
    day_offset = int(request.args.get("days", 20))
    sim_time = _reference_time + timedelta(days=day_offset)

    if not _original_iocs:
        return jsonify({"status": "error", "message": "Load a feed first"}), 400

    rows = compare(_original_iocs, sim_time)
    chart_path = generate_comparison_chart(rows)

    return jsonify({
        "status": "ok",
        "day_offset": day_offset,
        "rows": rows,
        "chart": _img_to_base64(chart_path) if chart_path else None,
    })


# ── API: Evaluation ─────────────────────────────────────────────────────────

@app.route("/api/evaluation", methods=["GET"])
def api_evaluation():
    day_offset = int(request.args.get("days", 20))
    sim_time = _reference_time + timedelta(days=day_offset)

    if not _original_iocs:
        return jsonify({"status": "error", "message": "Load a feed first"}), 400

    # Only IOCs with ground truth labels
    labeled = [i for i in _original_iocs if i.ground_truth_active is not None]
    if not labeled:
        return jsonify({"status": "error",
                        "message": "No ground-truth labels. Use simulation feed."}), 400

    ground_truth = [i.ground_truth_active for i in labeled]
    static_list  = static_scoring(labeled)
    decay_list   = decay_scoring(labeled, sim_time)

    static_scores   = [i.current_confidence for i in static_list]
    decay_scores    = [i.current_confidence for i in decay_list]
    weighted_scores = [i.weighted_score for i in decay_list]

    results = full_evaluation(static_scores, decay_scores, weighted_scores, ground_truth)

    # Generate charts
    roc_path = plot_roc_curves(static_scores, decay_scores, weighted_scores, ground_truth)
    metrics_path = plot_metrics_comparison(results)
    fpr_path = plot_fpr_comparison(results)
    f1_path = plot_f1_vs_threshold(static_scores, decay_scores, weighted_scores, ground_truth)

    # AUC values
    _, _, auc_static   = compute_auc_roc(static_scores, ground_truth)
    _, _, auc_decay    = compute_auc_roc(decay_scores, ground_truth)
    _, _, auc_weighted = compute_auc_roc(weighted_scores, ground_truth)
    results["static"]["auc"]   = auc_static
    results["decay"]["auc"]    = auc_decay
    results["weighted"]["auc"] = auc_weighted

    # Multi-threshold sweep for paper tables
    sweep = threshold_sweep(static_scores, decay_scores, weighted_scores, ground_truth)

    return jsonify({
        "status": "ok",
        "day_offset": day_offset,
        "total_iocs": len(labeled),
        "active_count": sum(ground_truth),
        "retired_count": len(ground_truth) - sum(ground_truth),
        "results": results,
        "threshold_sweep": sweep,
        "charts": {
            "roc": _img_to_base64(roc_path) if roc_path else None,
            "metrics": _img_to_base64(metrics_path) if metrics_path else None,
            "fpr": _img_to_base64(fpr_path) if fpr_path else None,
            "f1_threshold": _img_to_base64(f1_path) if f1_path else None,
        },
    })


# ── API: Robust Evaluation (multi-seed + cross-val + multi-decay) ───────────

@app.route("/api/robust-evaluation", methods=["GET"])
def api_robust_evaluation():
    """Run robust evaluation: 10 seeds × 4 decay models + static baseline."""
    from robust_evaluation import (
        multi_seed_evaluation,
        plot_multi_decay_comparison,
        plot_cv_f1_comparison,
        plot_multi_seed_boxplot,
    )

    day_offset = int(request.args.get("days", 15))
    n_seeds    = int(request.args.get("seeds", 10))

    summary = multi_seed_evaluation(n_seeds=n_seeds, n_iocs=200, day_offset=day_offset)

    # Generate charts
    auc_path = plot_multi_decay_comparison(summary)
    f1_path  = plot_cv_f1_comparison(summary)
    box_path = plot_multi_seed_boxplot(summary)

    return jsonify({
        "status": "ok",
        "n_seeds": n_seeds,
        "day_offset": day_offset,
        "summary": summary,
        "charts": {
            "multi_decay_auc": _img_to_base64(auc_path) if auc_path else None,
            "cv_f1":           _img_to_base64(f1_path) if f1_path else None,
            "auc_boxplot":     _img_to_base64(box_path) if box_path else None,
        },
    })


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("\n  ╔═══════════════════════════════════════════════════════════╗")
    print("  ║  Adaptive Time-Decay Threat Indicator Scoring Dashboard  ║")
    print("  ║  Open → http://localhost:5000                            ║")
    print("  ╚═══════════════════════════════════════════════════════════╝\n")
    app.run(debug=True, port=5000)
