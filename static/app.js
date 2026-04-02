/* ═══════════════════════════════════════════════════════════════
   app.js — Frontend logic for the Decay Engine Dashboard
   ═══════════════════════════════════════════════════════════════ */

let feedLoaded = false;
let currentDay = 0;

/* ── Helpers ─────────────────────────────────────────────────── */
function showStatus(msg, type = "info") {
    const el = document.getElementById("status-banner");
    el.className = `status-banner ${type}`;
    el.textContent = msg;
    el.classList.remove("hidden");
    setTimeout(() => el.classList.add("hidden"), 5000);
}

function confColor(score) {
    if (score >= 70) return "#22c55e";
    if (score >= 50) return "#f59e0b";
    if (score >= 30) return "#f97316";
    return "#ef4444";
}

function sevClass(sev) {
    return `sev-${(sev || "medium").toLowerCase()}`;
}

function truncate(str, len = 35) {
    return str.length > len ? str.slice(0, len) + "…" : str;
}

function sourceClass(src) {
    const s = (src || "default").toLowerCase().replace(/[\s-]/g, "_");
    return `src-${s}`;
}

/* ── Feed Status (check on page load) ────────────────────────── */
async function checkFeedStatus() {
    try {
        const resp = await fetch("/api/feed-status");
        const data = await resp.json();
        const row = document.getElementById("feed-status-row");
        let html = "";
        let anyConfigured = false;

        for (const [key, info] of Object.entries(data)) {
            const cls = info.configured ? "configured" : "missing";
            const label = info.configured ? "✓ Key set" : "⚠ No key";
            html += `<span class="feed-status-chip ${cls}">
                <span class="dot"></span>
                ${info.icon} ${info.name} — ${label}
            </span>`;

            // Enable the matching button
            const btn = document.getElementById(`btn-live-${key}`);
            if (btn && info.configured) {
                btn.disabled = false;
                anyConfigured = true;
            }
        }

        row.innerHTML = html;

        // Enable "Load All" if any feed is configured
        const btnAll = document.getElementById("btn-live-all");
        if (btnAll && anyConfigured) {
            btnAll.disabled = false;
        }
    } catch (e) {
        const row = document.getElementById("feed-status-row");
        row.innerHTML = `<span class="hint" style="color:var(--danger)">Could not check feed status — is the server running?</span>`;
    }
}

// Check feed status when page loads
document.addEventListener("DOMContentLoaded", checkFeedStatus);

/* ── Load Feed (sample / simulation) ─────────────────────────── */
async function loadFeed(type) {
    const btn = type === "sample"
        ? document.getElementById("btn-load-sample")
        : document.getElementById("btn-load-sim");
    btn.innerHTML = `<span class="spinner"></span> Loading…`;
    btn.disabled = true;

    try {
        const resp = await fetch("/api/load-feed", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ feed_type: type }),
        });
        const data = await resp.json();

        if (data.status === "ok") {
            feedLoaded = true;
            renderIOCTable(data.iocs);
            document.getElementById("ioc-section").classList.remove("hidden");
            document.getElementById("ioc-count").textContent = `${data.count} IOCs`;
            document.getElementById("day-slider").disabled = false;
            document.getElementById("day-slider").value = 20;
            document.getElementById("day-label").textContent = "Day 20";
            document.getElementById("btn-compare").disabled = false;
            document.getElementById("btn-evaluate").disabled = (type !== "simulation");
            currentDay = 20;

            // Hide previous comparison/evaluation
            document.getElementById("comparison-section").classList.add("hidden");
            document.getElementById("evaluation-section").classList.add("hidden");

            // Start from a non-zero day so decay differences are visible immediately.
            applyDecay(currentDay);

            showStatus(`✔ Loaded ${data.count} IOCs from ${type} feed`, "success");
        }
    } catch (e) {
        showStatus(`Error loading feed: ${e.message}`, "error");
    }

    btn.innerHTML = type === "sample" ? "📥 Load Sample Feed" : "🧪 Generate Simulation Data (200 IOCs)";
    btn.disabled = false;
}

/* ── Load Live Feed ──────────────────────────────────────────── */
async function loadLiveFeed(sources) {
    // Find which button was clicked for loading state
    let btnId = "btn-live-all";
    if (sources && sources.length === 1) {
        btnId = `btn-live-${sources[0]}`;
    }
    const btn = document.getElementById(btnId);
    const originalHTML = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Fetching live IOCs…`;
    btn.disabled = true;

    const limit = parseInt(document.getElementById("live-limit").value) || 50;
    const days = parseInt(document.getElementById("live-days").value) || 7;

    try {
        const resp = await fetch("/api/load-live-feed", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sources, limit, days }),
        });
        const data = await resp.json();

        if (data.status === "ok") {
            feedLoaded = true;
            renderIOCTable(data.iocs);
            document.getElementById("ioc-section").classList.remove("hidden");
            document.getElementById("ioc-count").textContent = `${data.count} IOCs`;
            document.getElementById("day-slider").disabled = false;
            document.getElementById("day-slider").value = 0;
            document.getElementById("day-label").textContent = "Day 0";
            document.getElementById("btn-compare").disabled = false;
            document.getElementById("btn-evaluate").disabled = true; // no ground truth for live
            currentDay = 0;

            // Hide previous comparison/evaluation
            document.getElementById("comparison-section").classList.add("hidden");
            document.getElementById("evaluation-section").classList.add("hidden");

            const srcLabel = sources ? sources.join(", ") : "all configured";
            showStatus(`✔ Loaded ${data.count} live IOCs from: ${srcLabel}`, "success");
        } else {
            showStatus(`⚠ ${data.message}`, "error");
        }
    } catch (e) {
        showStatus(`Live feed error: ${e.message}`, "error");
    }

    btn.innerHTML = originalHTML;
    btn.disabled = false;
}

/* ── Render IOC Table ────────────────────────────────────────── */
function renderIOCTable(iocs) {
    const tbody = document.getElementById("ioc-tbody");
    tbody.innerHTML = "";

    for (const ioc of iocs) {
        const conf = ioc.current_confidence;
        const weighted = ioc.weighted_score || 0;
        const color = confColor(conf);
        const isStale = ioc.is_stale;

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td title="${ioc.value}">${truncate(ioc.value, 38)}</td>
            <td>${ioc.indicator_type}</td>
            <td><span class="${sevClass(ioc.severity)}" style="font-weight:600">${(ioc.severity || "high").toUpperCase()}</span></td>
            <td><span class="source-badge ${sourceClass(ioc.source)}">${ioc.source || "—"}</span></td>
            <td>
                <div class="conf-bar">
                    <div class="bar-track">
                        <div class="bar-fill" style="width:${conf}%;background:${color}"></div>
                    </div>
                    <span class="bar-value" style="color:${color}">${conf.toFixed(1)}</span>
                </div>
            </td>
            <td style="color:${confColor(weighted)};font-weight:600">${weighted.toFixed(1)}</td>
            <td>
                <span class="pill ${isStale ? 'pill-stale' : 'pill-active'}">
                    ${isStale ? '🔴 Stale' : '🟢 Active'}
                </span>
            </td>
            <td>
                <button class="btn btn-sm btn-boost" onclick="boostIOC('${ioc.value.replace(/'/g, "\\'")}')">
                    ⚡ Boost
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    }
}

/* ── Day Slider ──────────────────────────────────────────────── */
let sliderTimeout = null;
function onSliderChange(val) {
    currentDay = parseInt(val);
    document.getElementById("day-label").textContent = `Day ${currentDay}`;

    clearTimeout(sliderTimeout);
    sliderTimeout = setTimeout(() => applyDecay(currentDay), 250);
}

async function applyDecay(days) {
    if (!feedLoaded) return;
    try {
        const resp = await fetch("/api/apply-decay", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ days }),
        });
        const data = await resp.json();
        if (data.status === "ok") {
            renderIOCTable(data.iocs);
            showStatus(`Decay applied at Day ${days}  (${data.sim_time})`, "info");
        }
    } catch (e) {
        showStatus(`Decay error: ${e.message}`, "error");
    }
}

/* ── Boost ───────────────────────────────────────────────────── */
async function boostIOC(value) {
    try {
        const resp = await fetch("/api/boost", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ value }),
        });
        const data = await resp.json();
        if (data.status === "ok") {
            showStatus(`⚡ Boosted ${truncate(value, 30)} → confidence ${data.ioc.current_confidence.toFixed(1)}`, "success");
            applyDecay(currentDay);      // refresh table
        }
    } catch (e) {
        showStatus(`Boost error: ${e.message}`, "error");
    }
}

/* ── Comparison ──────────────────────────────────────────────── */
async function runComparison() {
    const btn = document.getElementById("btn-compare");
    btn.innerHTML = `<span class="spinner"></span> Comparing…`;
    btn.disabled = true;

    try {
        const resp = await fetch(`/api/comparison?days=${currentDay}`);
        const data = await resp.json();

        if (data.status === "ok") {
            const section = document.getElementById("comparison-section");
            section.classList.remove("hidden");

            // Chart
            const chartDiv = document.getElementById("comparison-chart");
            chartDiv.innerHTML = data.chart
                ? `<img src="${data.chart}" alt="Static vs Decay comparison chart">`
                : "";

            // Table
            const tbody = document.getElementById("comparison-tbody");
            tbody.innerHTML = "";
            for (const r of data.rows) {
                const tr = document.createElement("tr");
                const gt = r.ground_truth;
                const gtLabel = gt === true ? "Active" : gt === false ? "Retired" : "—";
                const gtClass = gt === true ? "pill-active" : gt === false ? "pill-retired" : "";

                tr.innerHTML = `
                    <td title="${r.value}">${truncate(r.value, 30)}</td>
                    <td>${r.type}</td>
                    <td>${r.days_old}</td>
                    <td><span class="pill ${gtClass}">${gtLabel}</span></td>
                    <td style="color:${confColor(r.static_score)};font-weight:600">${r.static_score.toFixed(1)}</td>
                    <td><span class="pill ${r.static_flag === 'active' ? 'pill-active' : 'pill-stale'}">${r.static_flag}</span></td>
                    <td style="color:${confColor(r.decay_score)};font-weight:600">${r.decay_score.toFixed(1)}</td>
                    <td><span class="pill ${r.decay_flag === 'active' ? 'pill-active' : 'pill-stale'}">${r.decay_flag}</span></td>
                    <td style="font-weight:600">${r.weighted_score.toFixed(1)}</td>
                `;
                tbody.appendChild(tr);
            }
            section.scrollIntoView({ behavior: "smooth" });
            showStatus(`Comparison generated for Day ${data.day_offset}`, "success");
        }
    } catch (e) {
        showStatus(`Comparison error: ${e.message}`, "error");
    }

    btn.innerHTML = "📊 Compare Static vs Decay";
    btn.disabled = false;
}

/* ── Evaluation ──────────────────────────────────────────────── */
async function runEvaluation() {
    const btn = document.getElementById("btn-evaluate");
    btn.innerHTML = `<span class="spinner"></span> Evaluating…`;
    btn.disabled = true;

    try {
        const resp = await fetch(`/api/evaluation?days=${currentDay}`);
        const data = await resp.json();

        if (data.status === "error") {
            showStatus(data.message, "error");
            btn.innerHTML = "📈 Run Evaluation Metrics";
            btn.disabled = false;
            return;
        }

        const section = document.getElementById("evaluation-section");
        section.classList.remove("hidden");

        // Summary cards
        const summaryDiv = document.getElementById("eval-summary");
        const r = data.results;
        const fprReduction = r.static.fpr > 0
            ? ((1 - r.decay.fpr / r.static.fpr) * 100).toFixed(0) : "N/A";

        summaryDiv.innerHTML = `
            <div class="eval-card">
                <div class="metric-label">Total IOCs</div>
                <div class="metric-value" style="color:var(--accent)">${data.total_iocs}</div>
            </div>
            <div class="eval-card">
                <div class="metric-label">Active (Ground Truth)</div>
                <div class="metric-value" style="color:var(--success)">${data.active_count}</div>
            </div>
            <div class="eval-card">
                <div class="metric-label">Retired (Ground Truth)</div>
                <div class="metric-value" style="color:var(--danger)">${data.retired_count}</div>
            </div>
            <div class="eval-card">
                <div class="metric-label">FPR Reduction (Decay)</div>
                <div class="metric-value" style="color:var(--success)">${fprReduction}%</div>
            </div>
        `;

        // ── Optimal Threshold Info ──
        const optDiv = document.getElementById("optimal-thresholds") || createSection("optimal-thresholds", "eval-summary");
        let optHTML = `<h3 style="color:var(--accent);margin-top:1.5rem">⎯ Optimal Operating Points (Max F1)</h3>
            <div class="eval-summary" style="margin-top:0.5rem;">`;

        for (const [method, color] of [["static", "#e74c3c"], ["decay", "#22c55e"], ["weighted", "#3498db"]]) {
            const m = r[method];
            optHTML += `
                <div class="eval-card">
                    <div class="metric-label" style="color:${color}">${method.charAt(0).toUpperCase() + method.slice(1)} — Optimal</div>
                    <div class="metric-value" style="color:${color};font-size:1.5rem">F1 = ${(m.optimal_f1 || 0).toFixed(3)}</div>
                    <div style="font-size:.75rem;color:#aaa;margin-top:.3rem">
                        Threshold = ${m.optimal_threshold || "—"}<br>
                        P = ${(m.optimal_precision || 0).toFixed(3)} &nbsp; R = ${(m.optimal_recall || 0).toFixed(3)}<br>
                        FPR = ${(m.optimal_fpr || 0).toFixed(3)} &nbsp; Acc = ${(m.optimal_accuracy || 0).toFixed(3)}
                    </div>
                </div>`;
        }
        optHTML += `</div>`;
        optDiv.innerHTML = optHTML;

        // Metrics comparison table at the DEFAULT threshold
        const tableWrap = document.getElementById("metrics-table-wrap");
        const metrics = ["precision", "recall", "f1", "fpr", "accuracy", "auc"];
        const labels = ["Precision", "Recall (TPR)", "F1 Score", "False Positive Rate", "Accuracy", "AUC-ROC"];

        let tableHTML = `<h3 style="color:var(--accent);margin-top:1.5rem">⎯ Metrics at Default Threshold (${STALE_THRESHOLD})</h3>
            <table>
            <thead><tr>
                <th>Metric</th>
                <th style="color:#e74c3c">Static</th>
                <th style="color:#22c55e">Decay</th>
                <th style="color:#3498db">Weighted</th>
                <th>Winner</th>
            </tr></thead><tbody>`;

        for (let i = 0; i < metrics.length; i++) {
            const m = metrics[i];
            const sv = r.static[m] || 0;
            const dv = r.decay[m] || 0;
            const wv = r.weighted[m] || 0;

            let winner;
            if (m === "fpr") {
                winner = sv < dv && sv < wv ? "Static" : dv < wv ? "Decay" : "Weighted";
            } else {
                winner = sv > dv && sv > wv ? "Static" : dv > wv ? "Decay" : "Weighted";
            }
            const winColor = winner === "Static" ? "#e74c3c" : winner === "Decay" ? "#22c55e" : "#3498db";

            tableHTML += `<tr>
                <td style="font-family:var(--font);font-weight:600">${labels[i]}</td>
                <td>${sv.toFixed(4)}</td>
                <td>${dv.toFixed(4)}</td>
                <td>${wv.toFixed(4)}</td>
                <td style="color:${winColor};font-weight:700">${winner}</td>
            </tr>`;
        }
        tableHTML += `</tbody></table>`;
        tableWrap.innerHTML = tableHTML;

        // ── Threshold Sweep Table ──
        if (data.threshold_sweep) {
            const sweepDiv = document.getElementById("sweep-table-wrap") || createSection("sweep-table-wrap", "metrics-table-wrap");
            let sweepHTML = `<h3 style="color:var(--accent);margin-top:1.5rem">⎯ Threshold Sensitivity Analysis</h3>
                <div style="overflow-x:auto"><table>
                <thead><tr>
                    <th>Threshold</th>
                    <th colspan="3" style="color:#e74c3c;border-bottom:2px solid #e74c3c">Static</th>
                    <th colspan="3" style="color:#22c55e;border-bottom:2px solid #22c55e">Decay</th>
                    <th colspan="3" style="color:#3498db;border-bottom:2px solid #3498db">Weighted</th>
                </tr><tr>
                    <th></th>
                    <th>F1</th><th>FPR</th><th>Acc</th>
                    <th>F1</th><th>FPR</th><th>Acc</th>
                    <th>F1</th><th>FPR</th><th>Acc</th>
                </tr></thead><tbody>`;

            for (const row of data.threshold_sweep) {
                sweepHTML += `<tr>
                    <td style="font-weight:600">${row.threshold}</td>
                    <td>${row.static.f1.toFixed(3)}</td><td>${row.static.fpr.toFixed(3)}</td><td>${row.static.accuracy.toFixed(3)}</td>
                    <td>${row.decay.f1.toFixed(3)}</td><td>${row.decay.fpr.toFixed(3)}</td><td>${row.decay.accuracy.toFixed(3)}</td>
                    <td>${row.weighted.f1.toFixed(3)}</td><td>${row.weighted.fpr.toFixed(3)}</td><td>${row.weighted.accuracy.toFixed(3)}</td>
                </tr>`;
            }
            sweepHTML += `</tbody></table></div>`;
            sweepDiv.innerHTML = sweepHTML;
        }

        // Charts
        const chartsDiv = document.getElementById("eval-charts");
        chartsDiv.innerHTML = "";
        if (data.charts.roc) chartsDiv.innerHTML += `<img src="${data.charts.roc}" alt="ROC Curves">`;
        if (data.charts.metrics) chartsDiv.innerHTML += `<img src="${data.charts.metrics}" alt="Metrics Comparison">`;
        if (data.charts.fpr) chartsDiv.innerHTML += `<img src="${data.charts.fpr}" alt="FPR Comparison">`;
        if (data.charts.f1_threshold) chartsDiv.innerHTML += `<img src="${data.charts.f1_threshold}" alt="F1 vs Threshold">`;

        section.scrollIntoView({ behavior: "smooth" });
        showStatus("Evaluation complete!", "success");
    } catch (e) {
        showStatus(`Evaluation error: ${e.message}`, "error");
    }

    btn.innerHTML = "📈 Run Evaluation Metrics";
    btn.disabled = false;
}

/* ── Helper: create dynamic section ─────────────────────────── */
const STALE_THRESHOLD = 20;  // match config.py

function createSection(id, afterId) {
    let el = document.getElementById(id);
    if (!el) {
        el = document.createElement("div");
        el.id = id;
        const ref = document.getElementById(afterId);
        if (ref && ref.parentNode) {
            ref.parentNode.insertBefore(el, ref.nextSibling);
        } else {
            document.getElementById("evaluation-section").appendChild(el);
        }
    }
    return el;
}

/* ── Robust Evaluation (multi-seed × multi-decay) ───────────── */
async function runRobustEval() {
    const btn = document.getElementById("btn-robust");
    btn.innerHTML = `<span class="spinner"></span> Running 10 seeds × 4 models… (this takes ~30s)`;
    btn.disabled = true;

    try {
        const resp = await fetch(`/api/robust-evaluation?days=${currentDay || 15}&seeds=10`);
        const data = await resp.json();

        if (data.status !== "ok") {
            showStatus("Robust evaluation failed", "error");
            btn.innerHTML = "🔬 Robust Evaluation (10 Seeds × 4 Models)";
            btn.disabled = false;
            return;
        }

        const section = document.getElementById("robust-section");
        section.classList.remove("hidden");

        // Summary cards
        const summaryDiv = document.getElementById("robust-summary");
        const s = data.summary;
        const expAUC = s.exponential ? s.exponential.auc_mean : 0;
        const staAUC = s.static ? s.static.auc_mean : 0;
        summaryDiv.innerHTML = `
            <div class="eval-card">
                <div class="metric-label">Seeds</div>
                <div class="metric-value" style="color:var(--accent)">${data.n_seeds}</div>
            </div>
            <div class="eval-card">
                <div class="metric-label">Day Offset</div>
                <div class="metric-value" style="color:var(--accent)">${data.day_offset}</div>
            </div>
            <div class="eval-card">
                <div class="metric-label">Decay AUC (Mean)</div>
                <div class="metric-value" style="color:#22c55e">${expAUC.toFixed(3)}</div>
            </div>
            <div class="eval-card">
                <div class="metric-label">AUC Improvement</div>
                <div class="metric-value" style="color:#22c55e">${staAUC > 0 ? (((expAUC - staAUC) / staAUC) * 100).toFixed(0) : '—'}%</div>
            </div>
        `;

        // Comparison table: mean ± std for each model
        const tableWrap = document.getElementById("robust-table-wrap");
        const models = ["static", "exponential", "linear", "sigmoid", "power_law"];
        const modelColors = { "static": "#888", "exponential": "#22c55e", "linear": "#e74c3c", "sigmoid": "#f59e0b", "power_law": "#3498db" };
        const metrics = ["auc", "opt_f1", "cv_f1", "fpr", "precision", "recall", "accuracy"];
        const labels = ["AUC-ROC", "Optimal F1", "CV F1 (5-fold)", "FPR (at opt)", "Precision", "Recall", "Accuracy"];

        let html = `<h3 style="color:var(--accent);margin-top:1rem">⎯ Multi-Model Comparison (Mean ± Std, ${data.n_seeds} Seeds)</h3>
            <div style="overflow-x:auto"><table>
            <thead><tr><th>Metric</th>`;

        for (const m of models) {
            if (!s[m]) continue;
            html += `<th style="color:${modelColors[m]}">${m}</th>`;
        }
        html += `</tr></thead><tbody>`;

        for (let i = 0; i < metrics.length; i++) {
            const key = metrics[i];
            html += `<tr><td style="font-weight:600">${labels[i]}</td>`;
            const isLowerBetter = key === "fpr";

            let bestVal = isLowerBetter ? Infinity : -Infinity;
            let bestModel = "";

            // Find best model
            for (const m of models) {
                if (!s[m]) continue;
                const v = s[m][key + "_mean"] || 0;
                if (isLowerBetter ? v < bestVal : v > bestVal) {
                    bestVal = v;
                    bestModel = m;
                }
            }

            for (const m of models) {
                if (!s[m]) continue;
                const mean = s[m][key + "_mean"] || 0;
                const std = s[m][key + "_std"] || 0;
                const isBest = m === bestModel;
                html += `<td style="${isBest ? 'font-weight:700;color:' + modelColors[m] : ''}">${mean.toFixed(3)}±${std.toFixed(3)}</td>`;
            }
            html += `</tr>`;
        }
        html += `</tbody></table></div>`;
        tableWrap.innerHTML = html;

        // Charts
        const chartsDiv = document.getElementById("robust-charts");
        chartsDiv.innerHTML = "";
        if (data.charts.multi_decay_auc) chartsDiv.innerHTML += `<img src="${data.charts.multi_decay_auc}" alt="Multi-Decay AUC">`;
        if (data.charts.cv_f1) chartsDiv.innerHTML += `<img src="${data.charts.cv_f1}" alt="CV F1 Comparison">`;
        if (data.charts.auc_boxplot) chartsDiv.innerHTML += `<img src="${data.charts.auc_boxplot}" alt="AUC Boxplot">`;

        section.scrollIntoView({ behavior: "smooth" });
        showStatus("Robust evaluation complete!", "success");
    } catch (e) {
        showStatus(`Robust evaluation error: ${e.message}`, "error");
    }

    btn.innerHTML = "🔬 Robust Evaluation (10 Seeds × 4 Models)";
    btn.disabled = false;
}
