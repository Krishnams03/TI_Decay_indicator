#!/usr/bin/env python3
"""
main.py — CLI entry-point for the Adaptive Time-Decay Threat Indicator Engine.

Workflow:
  1. Load sample IOC feed → ingest into store
  2. Simulate time passage   (apply decay at day 5, 10, 20, 30)
  3. Simulate re-observation (boost at day 15)
  4. Print priority list & stale indicators
  5. Generate all charts
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

from config import SAMPLE_FEED_PATH, IOC_DATABASE_PATH, OUTPUT_DIR
from models import IOC
from ioc_store import IOCStore
from feed_loader import load_sample_feed
from confidence_updater import (
    update_all,
    reinforce,
    get_priority_list,
    get_active_indicators,
    get_stale_indicators,
)
from visualizer import plot_decay_curves, plot_ioc_confidence, plot_adaptive_scenario


SEPARATOR = "═" * 72


def _header(title: str) -> None:
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def main() -> None:
    # ── 1. Load sample feed ──────────────────────────────────────────────
    _header("STEP 1 — Loading Sample Threat Feed")
    iocs = load_sample_feed(SAMPLE_FEED_PATH)
    print(f"  Loaded {len(iocs)} indicators from {SAMPLE_FEED_PATH}\n")

    store = IOCStore(IOC_DATABASE_PATH)
    for ioc in iocs:
        store.add_ioc(ioc)
    store.save()
    print(f"  Ingested into IOC store ({len(store)} entries)")

    # ── 2. Show initial state ────────────────────────────────────────────
    _header("STEP 2 — Initial Confidence Scores")
    for ioc in get_priority_list(store):
        print(f"  [{ioc.indicator_type.value:>9}]  {ioc.value:<52}  "
              f"confidence = {ioc.current_confidence:6.2f}")

    # ── 3. Simulate decay at several time-points ─────────────────────────
    base_time = datetime(2026, 2, 15, 0, 0, 0)      # "today" for simulation
    checkpoints = [5, 10, 15, 20, 30]

    for day in checkpoints:
        sim_time = base_time + timedelta(days=day)
        _header(f"STEP 3.{day} — Applying Decay  (Day {day}  →  {sim_time.date()})")

        # Reload original scores so each checkpoint is independent
        store_snap = IOCStore(IOC_DATABASE_PATH)
        store_snap.load()
        update_all(store_snap, sim_time)

        # ── Re-observation boost at Day 15 ───────────────────────────────
        if day == 15:
            print("  ⚡ Re-observation of 203.0.113.50 in firewall logs!")
            reinforce(store_snap, "203.0.113.50", sim_time)

        active = get_active_indicators(store_snap)
        stale  = get_stale_indicators(store_snap)

        print(f"\n  Active indicators ({len(active)}):")
        for ioc in active:
            print(f"    [{ioc.indicator_type.value:>9}]  {ioc.value:<52}  "
                  f"confidence = {ioc.current_confidence:6.2f}")

        if stale:
            print(f"\n  ⚠ Stale indicators ({len(stale)}):")
            for ioc in stale:
                print(f"    [{ioc.indicator_type.value:>9}]  {ioc.value:<52}  "
                      f"confidence = {ioc.current_confidence:6.2f}")

    # ── 4. Final prioritized list (Day 30 snapshot) ──────────────────────
    _header("STEP 4 — Final Priority List  (Day 30)")
    store_final = IOCStore(IOC_DATABASE_PATH)
    store_final.load()
    sim_final = base_time + timedelta(days=30)
    update_all(store_final, sim_final)

    for rank, ioc in enumerate(get_priority_list(store_final), 1):
        status = "🔴 STALE" if ioc.is_stale else "🟢 ACTIVE"
        print(f"  #{rank:<3}  {status}  [{ioc.indicator_type.value:>9}]  "
              f"{ioc.value:<52}  confidence = {ioc.current_confidence:6.2f}")

    store_final.save()

    # ── 5. Generate charts ───────────────────────────────────────────────
    _header("STEP 5 — Generating Visualizations")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    p1 = plot_decay_curves()
    print(f"  ✔ Decay curves chart       → {p1}")

    p2 = plot_ioc_confidence(store_final)
    print(f"  ✔ IOC confidence bar chart  → {p2}")

    p3 = plot_adaptive_scenario()
    print(f"  ✔ Adaptive scenario chart   → {p3}")

    _header("DONE")
    print("  All outputs saved.  Open the 'output/' folder to view charts.\n")


if __name__ == "__main__":
    main()
