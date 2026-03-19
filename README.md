# Adaptive Time-Decay Threat Indicator Scoring Engine

An experimental threat-intelligence scoring engine that models **confidence decay** for Indicators of Compromise (IOCs) over time, supports **adaptive re-observation boosts**, and exposes both:

- a **CLI workflow** for simulation and chart generation,
- and a **Flask dashboard + REST API** for interactive analysis.

The project compares static scoring vs decay-based scoring and includes reproducible evaluation pipelines (including multi-seed robust evaluation).

---

## What this project does

- Applies configurable time-decay to IOC confidence scores (per IOC type)
- Supports multiple decay models: exponential, linear, sigmoid, and power-law
- Adds adaptive confidence reinforcement when an IOC is re-observed
- Flags stale/archivable indicators using configurable thresholds
- Computes weighted prioritization scores using severity + source reliability
- Evaluates static vs decay scoring with classification metrics and ROC/AUC
- Provides charts and benchmark scripts for paper/report-style analysis

---

## Tech stack

- **Python 3.10+**
- **Flask** (web app and API)
- **Matplotlib** (chart generation)

---

## Repository layout

```text
.
├── app.py                  # Flask app + REST endpoints + dashboard host
├── main.py                 # CLI end-to-end run (load, decay, boost, charts)
├── decay_engine.py         # Core decay math + boost + stale/archive logic
├── confidence_updater.py   # Store-wide orchestration helpers
├── models.py               # IOC, enums, severity multipliers
├── ioc_store.py            # JSON-backed IOC storage
├── feed_loader.py          # Sample feed ingestion
├── simulation.py           # Labeled IOC dataset generator
├── comparison.py           # Static vs decay scoring comparison + chart
├── evaluation.py           # Metrics, ROC/AUC, threshold sweep + plots
├── robust_evaluation.py    # Multi-seed + cross-validated robust eval
├── visualizer.py           # Decay/IOC/adaptive scenario charting
├── benchmark.py            # Quick day-by-day benchmark script
├── tests/                  # Unit tests for decay_engine and ioc_store
├── data/
│   ├── sample_iocs.json    # Input sample feed
│   ├── ioc_database.json   # Store persistence
│   └── simulation_iocs.json
├── output/                 # Generated charts
├── static/                 # Frontend JS/CSS
└── templates/              # Dashboard HTML
```

---

## Quick start

### 1) Create and activate a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Run the CLI workflow

```bash
python main.py
```

This will:

1. Load sample feed IOCs
2. Simulate decay at day checkpoints
3. Apply a re-observation boost event
4. Print active/stale prioritization snapshots
5. Save charts into `output/`

### 4) Run the dashboard

```bash
python app.py
```

Then open: <http://localhost:5000>

Dashboard supports:

- loading sample or simulation feed,
- adjusting day offset via slider,
- boosting individual IOCs,
- static-vs-decay comparison,
- evaluation metrics and robust multi-seed evaluation.

---

## Running analysis scripts

### Benchmark across day offsets

```bash
python benchmark.py
```

### Robust multi-seed evaluation

```bash
python robust_evaluation.py
```

Generates summary output and charts in `output/`, including:

- `multi_decay_auc.png`
- `cv_f1_comparison.png`
- `auc_boxplot.png`

---

## Testing

You can run tests either with pytest or using direct script execution.

With pytest:

```bash
pytest -q
```

Direct script mode:

```bash
python tests/test_decay_engine.py
python tests/test_ioc_store.py
```

---

## API reference

Base URL: `http://localhost:5000`

- `GET /`
  - Serves dashboard UI
- `POST /api/load-feed`
  - Body: `{ "feed_type": "sample" | "simulation" }`
  - Loads sample feed or generates simulation dataset
- `POST /api/apply-decay`
  - Body: `{ "days": <int> }`
  - Re-applies decay from original loaded snapshot at given day offset
- `POST /api/boost`
  - Body: `{ "value": "<indicator>" }`
  - Applies adaptive boost to selected IOC
- `GET /api/comparison?days=<int>`
  - Returns static vs decay scoring rows and comparison chart
- `GET /api/evaluation?days=<int>`
  - Returns metrics, threshold sweep, ROC/AUC and chart payloads
- `GET /api/robust-evaluation?days=<int>&seeds=<int>`
  - Runs robust multi-seed + multi-decay model evaluation

---

## Core scoring concepts

- Exponential decay (default):

  \[
  C(t) = C_0 e^{-\lambda t}
  \]

- Weighted score used for prioritization:

  \[
  W(t) = C(t) \times \text{severity multiplier} \times \text{source reliability}
  \]

- Adaptive boost on re-observation:

  \[
  C_{new} = \min(C(t) + \alpha, C_{max})
  \]

Decay constants and thresholds are configured in `config.py`.

---

## Data files and outputs

- Input feed: `data/sample_iocs.json`
- JSON IOC store: `data/ioc_database.json`
- Simulation dataset (generated): `data/simulation_iocs.json`
- Charts and artifacts: `output/`

---

## Notes

- `tests/` currently covers core decay logic and IOC store persistence.
- Dependencies are pinned in `requirements.txt` for reproducible setup.
- The robust evaluation module may emit a Matplotlib deprecation warning for `boxplot(labels=...)` on newer Matplotlib versions, but execution still completes.
