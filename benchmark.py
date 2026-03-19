"""Quick benchmark: evaluate all three scoring methods at multiple time points."""
from simulation import generate_simulation_dataset
from comparison import static_scoring, decay_scoring
from evaluation import full_evaluation, compute_auc_roc
from datetime import datetime, timedelta

ref = datetime(2026, 2, 24, 0, 0, 0)
iocs = generate_simulation_dataset(200, reference_time=ref)

for day in [5, 10, 15, 20, 30]:
    sim = ref + timedelta(days=day)
    labeled = [i for i in iocs if i.ground_truth_active is not None]
    gt = [i.ground_truth_active for i in labeled]
    sl = static_scoring(labeled)
    dl = decay_scoring(labeled, sim)
    ss = [i.current_confidence for i in sl]
    ds = [i.current_confidence for i in dl]
    ws = [i.weighted_score for i in dl]
    r = full_evaluation(ss, ds, ws, gt)
    _, _, auc_s = compute_auc_roc(ss, gt)
    _, _, auc_d = compute_auc_roc(ds, gt)
    _, _, auc_w = compute_auc_roc(ws, gt)
    s = r["static"]
    d = r["decay"]
    w = r["weighted"]
    print(f"DAY {day:2d}")
    print(f"  Static:   F1={s['f1']:.4f}  FPR={s['fpr']:.4f}  Acc={s['accuracy']:.4f}  AUC={auc_s:.4f}  optF1={s['optimal_f1']:.4f}@t={s['optimal_threshold']}")
    print(f"  Decay:    F1={d['f1']:.4f}  FPR={d['fpr']:.4f}  Acc={d['accuracy']:.4f}  AUC={auc_d:.4f}  optF1={d['optimal_f1']:.4f}@t={d['optimal_threshold']}")
    print(f"  Weighted: F1={w['f1']:.4f}  FPR={w['fpr']:.4f}  Acc={w['accuracy']:.4f}  AUC={auc_w:.4f}  optF1={w['optimal_f1']:.4f}@t={w['optimal_threshold']}")
    print()
