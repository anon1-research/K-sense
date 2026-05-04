# K-Sense: A Non-Invasive eBPF Framework for QoS Inference

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Paper](https://img.shields.io/badge/Paper-IEEE%20ICFEC%202026-green)](https://icfec2026.ieee.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey)](https://www.kernel.org/)

K-Sense is a non-invasive, zero-instrumentation framework that infers application QoS
degradation purely from kernel-level signals. It attaches eBPF probes to the Linux scheduler,
I/O subsystem, and SoftIRQ path to observe CPU scheduling latency, D-state I/O latency, and
SoftIRQ processing time — without modifying or restarting any application.

System state is represented as a point in a multi-dimensional feature space. Deviation from a
calibrated baseline is quantified via the **Mahalanobis distance** (friction signal), augmented
with a directional sign and an adaptive energy signal that captures short-term instability.
This makes K-Sense suitable for QoS inference in edge and fog environments where applications
are black boxes and per-application instrumentation is impractical.

> **Paper accepted at IEEE ICFEC 2026.**
> Abdullah Muslim, Ali Beiti Aydenlou, Stephan Recker.
> *K-Sense: A Non-Invasive eBPF Framework for QoS Inference.*

---

## How It Works

1. **Calibration** — K-Sense observes the system under idle/baseline load and builds a statistical baseline from the three kernel signals.
2. **Inference** — At runtime, each new observation is compared to the baseline using the Mahalanobis distance (friction). A direction sign tracks whether the system is above or below baseline. An adaptive energy signal measures friction volatility.
3. **Output** — All signals are streamed to a CSV file for offline analysis or fed to an admission controller / scheduler.

## Repository Layout

```
src/ksense/             Python package (BPF program, friction, energy, collector, config)
main.py                 Entry point
node_collector/         Kernel event correlator — selects which signals best track latency
scripts/
  monitor_cpu_psi.py        CPU + PSI monitor (1-second CSV)
  step_response_prober.py   Step-response load generator for 3 apps (per-second CSV)
  latency_p99_prober.py     Parallel P99 latency prober for 3 apps (per-interval CSV)
kubernetes/             DaemonSet manifests (namespace, kustomization)
examples/               Sample output CSV showing calibration → load step → recovery
```

The prober scripts target [DeathStarBench](https://github.com/delimitrou/DeathStarBench)
microservices (Social Media, Hotel Reservation) and a sentiment-analysis app (not included).

## Requirements

- Linux kernel 4.20+ with BPF support (x86-64)
- `bcc` — install via system package manager:
  ```bash
  sudo apt-get install bpfcc-tools python3-bpfcc
  ```
- Python dependencies:
  ```bash
  pip install -r requirements.txt   # numpy>=1.21, requests>=2.25
  ```

## Quick Start

**K-Sense main collector** (friction + energy signals → `/tmp/ksense/kernel_metrics.csv`):

```bash
sudo -E python3 main.py
```

**Node-level correlation collector** (select which kernel signals track latency):

```bash
sudo -E python3 node_collector/main.py
```

**Measurement scripts** (point `--host` at your cluster node):

```bash
python3 scripts/monitor_cpu_psi.py
python3 scripts/step_response_prober.py --host <NODE_IP>
python3 scripts/latency_p99_prober.py   --host <NODE_IP> --feedback-input <path/to/input.json>
```

Both prober scripts also respect the `KSENSE_HOST` and `KSENSE_FEEDBACK_INPUT` environment variables.

## Docker

K-Sense requires privileged access for eBPF:

```bash
docker build -t ksense .
docker run --rm --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /lib/modules:/lib/modules:ro \
  ksense
```

## Kubernetes

The DaemonSet deploys one collector pod per node.

**Build and push the image first** (replace `<registry>` with your registry):

```bash
docker build -t <registry>/ksense:latest .
docker push <registry>/ksense:latest
```

Update the image reference in [kubernetes/daemonset.yaml](kubernetes/daemonset.yaml), then apply:

```bash
kubectl apply -k kubernetes/
```

Output is written to `/tmp/ksense/kernel_metrics.csv` inside each pod. Check status:

```bash
kubectl get ds   -n ksense
kubectl get pods -n ksense -l app=ksense -o wide
```

## Example Output

A sample [examples/kernel_metrics_sample.csv](examples/kernel_metrics_sample.csv) shows the
full lifecycle: baseline calibration, freeze, a load step, and recovery. Key columns:

| Column | Description |
|---|---|
| `Friction` | Mahalanobis distance from baseline |
| `Direction` | +1 above baseline, −1 below |
| `Energy` | Adaptive volatility of friction |
| `BaselineMode` | `CALIBRATING` → `FROZEN` |

## Citation

If you use K-Sense in your research, please cite:

```bibtex
@inproceedings{ksense2026,
  author    = {Abdullah Muslim and Ali Beiti Aydenlou and Stephan Recker},
  title     = {K-Sense: A Non-Invasive eBPF Framework for QoS Inference},
  booktitle = {Proceedings of the IEEE International Conference on Fog and Edge Computing (ICFEC)},
  year      = {2026},
}
```

## License

This project is licensed under the Apache License 2.0 — see [LICENSE](LICENSE) for details.
