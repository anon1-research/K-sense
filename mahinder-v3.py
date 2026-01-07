#!/usr/bin/env python3
import os
import time
import csv
from datetime import datetime
from collections import deque

import numpy as np

from bcc import BPF
import ctypes as ct

# -------------------------
# Collector cadence
# -------------------------
WINDOW_SEC = 1.0
GRID_STEP_S = 1  # should match WINDOW_SEC

# -------------------------
# Output files
# -------------------------
OUT_CSV  = "kernel_metrics.csv"
LIVE_PNG = "kernel_live.png"  # updated continuously in headless mode

# -------------------------
# Energy Settings (EMA)
# -------------------------
# Alpha controls smoothing: 0.05 = very smooth, 0.2 = responsive
ENERGY_ALPHA = 0.02

# -------------------------
# Mahalanobis friction config
# -------------------------
MAHAL_MIN_SAMPLES = 20
MAHAL_REG_REL = 1e-3
MAHAL_REG_ABS = 1e-9

# Baseline gating to prevent "learning overload"
# IMPORTANT: Keep system IDLE for first 2 minutes!
WARMUP_S = 300
# Chi-square 95% threshold for df=4: distance ~= sqrt(9.49) ~= 3.08
BASELINE_GATE_DIST = 3.08

# Baseline window size (how many baseline points we keep)
BASELINE_WIN_S = 5 * 60

# -------------------------
# Plotting controls
# -------------------------
ENABLE_PLOT = True
PLOT_WINDOW_MIN = 60
SAVE_PNG_EVERY_S = 10

# -------------------------
# Matplotlib backend (GUI vs headless)
# -------------------------
HEADLESS = (os.environ.get("DISPLAY", "") == "")
if ENABLE_PLOT:
    import matplotlib
    if HEADLESS:
        matplotlib.use("Agg")  # no GUI -> write PNG
    import matplotlib.pyplot as plt


# ============================================================
# eBPF program (NO retransmit)
# ============================================================
bpf_text = r"""
#include <linux/sched.h>

struct val_t {
    u64 sched_lat_us_sum;
    u64 sched_lat_cnt;
    u64 sched_lat_us_max;

    u64 dstate_us_sum;
    u64 dstate_cnt;

    u64 softirq_us_sum;
    u64 softirq_cnt;

    u64 sched_lat_dropped;
};

BPF_HASH(stats, u32, struct val_t);

BPF_HASH(ts_runnable, u32, u64);
BPF_HASH(ts_dstate, u32, u64);
BPF_HASH(ts_softirq, u32, u64);

BPF_HISTOGRAM(sched_lat_hist);

TRACEPOINT_PROBE(sched, sched_wakeup) {
    u32 pid = args->pid;
    u64 now = bpf_ktime_get_ns();

    u64 *dt = ts_dstate.lookup(&pid);
    if (dt) {
        if (now > *dt) {
            u64 delta_us = (now - *dt) / 1000;
            struct val_t *v, zero = {};
            u32 k = 0;
            v = stats.lookup_or_init(&k, &zero);
            if (v) {
                v->dstate_us_sum += delta_us;
                v->dstate_cnt += 1;
            }
        }
        ts_dstate.delete(&pid);
    }

    ts_runnable.update(&pid, &now);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup_new) {
    u32 pid = args->pid;
    u64 now = bpf_ktime_get_ns();
    ts_runnable.update(&pid, &now);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    u64 now = bpf_ktime_get_ns();

    if (args->prev_state == 0) {
        ts_runnable.update(&prev_pid, &now);
    }

    u64 *tsp = ts_runnable.lookup(&next_pid);
    if (tsp) {
        struct val_t *v, zero = {};
        u32 k = 0;
        v = stats.lookup_or_init(&k, &zero);

        if (v) {
            if (now > *tsp) {
                u64 delta_us = (now - *tsp) / 1000;

                v->sched_lat_us_sum += delta_us;
                v->sched_lat_cnt += 1;
                if (delta_us > v->sched_lat_us_max) v->sched_lat_us_max = delta_us;

                u64 bucket = delta_us ? bpf_log2l(delta_us) : 0;
                sched_lat_hist.increment(bucket);
            } else {
                v->sched_lat_dropped += 1;
            }
        }
        ts_runnable.delete(&next_pid);
    }

    if (args->prev_state & 2) {
        ts_dstate.update(&prev_pid, &now);
    }

    return 0;
}

TRACEPOINT_PROBE(irq, softirq_entry) {
    if (args->vec != 3) return 0;
    u32 cpu = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_ns();
    ts_softirq.update(&cpu, &now);
    return 0;
}

TRACEPOINT_PROBE(irq, softirq_exit) {
    if (args->vec != 3) return 0;
    u32 cpu = bpf_get_smp_processor_id();
    u64 *ts = ts_softirq.lookup(&cpu);
    if (ts) {
        u64 now = bpf_ktime_get_ns();
        if (now > *ts) {
            u64 delta_us = (now - *ts) / 1000;
            struct val_t *v, zero = {};
            u32 k = 0;
            v = stats.lookup_or_init(&k, &zero);
            if (v) {
                v->softirq_us_sum += delta_us;
                v->softirq_cnt += 1;
            }
        }
        ts_softirq.delete(&cpu);
    }
    return 0;
}
"""


# ============================================================
# Helpers
# ============================================================
def ensure_csv(path: str, header):
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(header)

def percentiles_from_log2_hist(items, ps=(0.95, 0.99)):
    buckets = sorted((int(k.value), int(v.value)) for k, v in items)
    total = sum(c for _, c in buckets)
    if total == 0:
        return {p: 0 for p in ps}
    targets = {p: int(total * p + 0.999999) for p in ps}
    out = {}
    running = 0
    for b, c in buckets:
        running += c
        for p, t in targets.items():
            if p not in out and running >= t:
                out[p] = (1 << b)  # us lower bound
    for p in ps:
        out.setdefault(p, (1 << buckets[-1][0]))
    return out

def mahalanobis_distance(x: np.ndarray, X: np.ndarray) -> float:
    """
    Mahalanobis distance of x to baseline samples X.
    Uses Cholesky on (Sigma + reg*I) for stability.
    Returns NaN if insufficient samples or ill-conditioned.
    """
    try:
        x = np.asarray(x, dtype=float).reshape(-1)
        X = np.asarray(X, dtype=float)
        if X.ndim != 2 or x.ndim != 1:
            return float("nan")
        if X.shape[1] != x.shape[0]:
            return float("nan")

        X = X[np.all(np.isfinite(X), axis=1)]
        if not np.all(np.isfinite(x)):
            return float("nan")

        d = x.shape[0]
        if X.shape[0] < max(MAHAL_MIN_SAMPLES, d + 2):
            return float("nan")

        mu = np.mean(X, axis=0)
        Sigma = np.cov(X, rowvar=False, bias=False)
        if Sigma.shape != (d, d) or not np.all(np.isfinite(Sigma)):
            return float("nan")

        diag = np.diag(Sigma)
        diag_mean = float(np.mean(diag)) if np.all(np.isfinite(diag)) else 0.0
        reg = MAHAL_REG_ABS + MAHAL_REG_REL * max(diag_mean, 0.0)
        Sigma_reg = Sigma + reg * np.eye(d)

        L = np.linalg.cholesky(Sigma_reg)
        diff = (x - mu).reshape(-1, 1)
        y = np.linalg.solve(L, diff)
        dist2 = float(np.dot(y[:, 0], y[:, 0]))
        return float(np.sqrt(max(dist2, 0.0)))
    except Exception:
        return float("nan")


# ============================================================
# Live plot
# ============================================================
class LivePlot:
    def __init__(self):
        if not HEADLESS:
            plt.ion()
        self.fig = plt.figure(figsize=(14, 7))
        self.ax1 = self.fig.add_subplot(2, 1, 1)
        self.ax2 = self.fig.add_subplot(2, 1, 2, sharex=self.ax1)

        (self.l_fric,) = self.ax1.plot([], [], label="Friction (Mahalanobis)", color='red')
        self.ax1.set_ylabel("Distance")
        self.ax1.grid(True, alpha=0.3)
        self.ax1.legend(loc="upper right")
        self.ax1.set_title("Mahalanobis Friction (Magnitude)")

        (self.l_eng,) = self.ax2.plot([], [], label="Energy (EMA)", color='orange')
        self.ax2.set_ylabel("Energy")
        self.ax2.grid(True, alpha=0.3)
        self.ax2.legend(loc="upper right")
        self.ax2.set_title("System Energy (Instability)")

        self.fig.tight_layout()

    def update(self, t, fric, eng):
        n = len(t)
        if not (len(fric) == n and len(eng) == n):
            return
        self.l_fric.set_data(t, fric)
        self.l_eng.set_data(t, eng)

        self.ax1.relim(); self.ax1.autoscale_view()
        self.ax2.relim(); self.ax2.autoscale_view()

        if not HEADLESS:
            self.fig.canvas.draw()
            self.fig.canvas.flush_events()
            plt.pause(0.001)

    def save(self, path: str):
        self.fig.savefig(path, dpi=140, bbox_inches="tight")


# ============================================================
# Main
# ============================================================
def main():
    headers = [
        "Time",
        "SchedLat_Total_ms", "SchedLat_Avg_ms", "SchedLat_P95_ms", "SchedLat_P99_ms", "SchedLat_Max_ms",
        "SchedLat_Count", "SchedLat_Dropped",
        "DState_Total_ms", "DState_Count",
        "SoftIRQ_Total_ms", "SoftIRQ_Count",
        "Friction",
        "dF_dt",        
        "Energy",       
    ]
    ensure_csv(OUT_CSV, headers)

    baseline_w = max(10, int(BASELINE_WIN_S / GRID_STEP_S))
    warmup_steps = max(10, int(WARMUP_S / GRID_STEP_S))

    plot_points = int((PLOT_WINDOW_MIN * 60) / GRID_STEP_S)
    keep_points = max(plot_points, baseline_w + 100)

    t_buf = deque(maxlen=keep_points)
    baseline_feat_b = deque(maxlen=baseline_w)

    fric_b = deque(maxlen=keep_points)
    dfr_b  = deque(maxlen=keep_points)
    eng_b  = deque(maxlen=keep_points)

    lp = LivePlot() if ENABLE_PLOT else None
    last_png_save = 0.0

    b = BPF(text=bpf_text)

    print("\n=== K-Sense Kernel Collector (Smoothed Energy) ===")
    print(f"Sampling Rate: {GRID_STEP_S}s")
    print(f"Energy Smoothing (Alpha): {ENERGY_ALPHA}")
    print(f"Warmup Period: {WARMUP_S}s (PLEASE KEEP SYSTEM IDLE)")
    print(f"Output: {OUT_CSV}")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(WINDOW_SEC)

            now = datetime.now()
            ts_str = now.strftime("%Y-%m-%d %H:%M:%S")
            t_buf.append(now)

            # --- read BPF stats ---
            sched_total_ms = sched_avg_ms = sched_p95_ms = sched_p99_ms = sched_max_ms = 0.0
            sched_cnt = 0
            sched_dropped = 0
            dstate_total_ms = 0.0
            dstate_cnt = 0
            softirq_total_ms = 0.0
            softirq_cnt = 0

            v = b["stats"].get(ct.c_uint(0))
            if v:
                sched_cnt = int(v.sched_lat_cnt)
                sched_dropped = int(v.sched_lat_dropped)
                sched_total_ms = float(v.sched_lat_us_sum) / 1000.0
                sched_max_ms = float(v.sched_lat_us_max) / 1000.0
                if sched_cnt > 0:
                    sched_avg_ms = sched_total_ms / sched_cnt

                pct = percentiles_from_log2_hist(b["sched_lat_hist"].items(), ps=(0.95, 0.99))
                sched_p95_ms = float(pct[0.95]) / 1000.0
                sched_p99_ms = float(pct[0.99]) / 1000.0

                dstate_total_ms = float(v.dstate_us_sum) / 1000.0
                dstate_cnt = int(v.dstate_cnt)

                softirq_total_ms = float(v.softirq_us_sum) / 1000.0
                softirq_cnt = int(v.softirq_cnt)

                b["stats"].clear()
                b["sched_lat_hist"].clear()

            # --- Feature vector ---
            x_t = np.array([
                sched_p99_ms,
                sched_total_ms,
                dstate_total_ms,
                softirq_total_ms,
            ], dtype=float)

            # --- Mahalanobis Friction ---
            if len(baseline_feat_b) < warmup_steps:
                # Still in warmup phase
                if np.all(np.isfinite(x_t)):
                    baseline_feat_b.append(x_t)
                friction = float("nan")
            else:
                # Calculate Distance
                Xbase = np.array(baseline_feat_b, dtype=float)
                friction = mahalanobis_distance(x_t, Xbase)

                # Update Baseline (Gating)
                # Only update if the system is "Normal" (low friction)
                if np.isfinite(friction) and (friction <= BASELINE_GATE_DIST) and np.all(np.isfinite(x_t)):
                    baseline_feat_b.append(x_t)

            fric_b.append(float(friction))

            # --- Energy (EMA) Calculation ---
            # 1. Calculate Instantaneous Derivative (dF/dt)
            if len(fric_b) >= 2 and np.isfinite(fric_b[-1]) and np.isfinite(fric_b[-2]):
                dF_dt = (fric_b[-1] - fric_b[-2]) / WINDOW_SEC
            else:
                dF_dt = float("nan")
            dfr_b.append(float(dF_dt))

            # 2. Calculate Smoothed Energy (Exponential Moving Average)
            current_instability = abs(dF_dt) if np.isfinite(dF_dt) else 0.0
            
            if len(eng_b) == 0 or np.isnan(eng_b[-1]):
                energy = current_instability
            else:
                # EMA Formula: New = (Alpha * Current) + ((1-Alpha) * Old)
                energy = ENERGY_ALPHA * current_instability + (1 - ENERGY_ALPHA) * eng_b[-1]
                
            eng_b.append(float(energy))

            # --- CSV Output ---
            with open(OUT_CSV, "a", newline="") as f:
                csv.writer(f).writerow([
                    ts_str,
                    f"{sched_total_ms:.2f}", f"{sched_avg_ms:.4f}", f"{sched_p95_ms:.4f}", f"{sched_p99_ms:.4f}", f"{sched_max_ms:.4f}",
                    sched_cnt, sched_dropped,
                    f"{dstate_total_ms:.2f}", dstate_cnt,
                    f"{softirq_total_ms:.2f}", softirq_cnt,
                    f"{friction:.6f}" if np.isfinite(friction) else "",
                    f"{dF_dt:.6f}" if np.isfinite(dF_dt) else "",
                    f"{energy:.6f}" if np.isfinite(energy) else "",
                ])

            # --- Plot Update ---
            if lp is not None:
                t_list = list(t_buf)[-plot_points:]
                fr_list = list(fric_b)[-plot_points:]
                en_list = list(eng_b)[-plot_points:]
                lp.update(t_list, fr_list, en_list)

                if HEADLESS:
                    now_t = time.time()
                    if (now_t - last_png_save) >= SAVE_PNG_EVERY_S:
                        lp.save(LIVE_PNG)
                        last_png_save = now_t

    except KeyboardInterrupt:
        print("\nStopping. Outputs saved:")
        print(f" - {OUT_CSV}")
        if ENABLE_PLOT and HEADLESS:
            print(f" - {LIVE_PNG}")


if __name__ == "__main__":
    main()
