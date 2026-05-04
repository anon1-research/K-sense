# K-Sense: A Non-Invasive eBPF Framework for QoS Inference

This repository contains the reference implementation for K-Sense, a non-invasive
eBPF-based framework that infers QoS degradation from kernel behavior by computing
a covariance-aware friction signal (Mahalanobis distance) plus a directional sign
and an adaptive energy signal.

Paper status: Accepted at IEEE ICFEC 2026.


## Layout

- `src/ksense/` Python package (BPF program, helpers, energy model, main loop)
- `main.py` Entry point script
- `scripts/monitor_cpu_psi.py` CPU + PSI monitoring helper script (CSV only, no plotting)
- `scripts/step_response_prober.py` Step-response load generator for 3 apps (per-second CSV). Uses DeathStarBench and a sentiment-analysis app:
  - https://github.com/delimitrou/DeathStarBench
  - sentiment-analysis app (not included in this repo)
- `scripts/latency_p99_prober.py` Parallel P99 latency prober for 3 apps (per-interval CSV). Uses the same app sources:
  - https://github.com/delimitrou/DeathStarBench
  - sentiment-analysis app (not included in this repo)
- `kubernetes/` Kubernetes manifests (namespace, DaemonSet, kustomization)
- `node_collector/` Node-level syscall + kernel signal collector (eBPF) used to
  compute correlations and select which kernel syscalls/tracepoints best track latency

## Run

There are two separate components:
1) `K-Sense` main collector (friction/energy signals)
2) `node_collector` (kernel event correlation to select signals)

K-Sense main collector:

```bash
sudo -E python3 main.py
```


Node-level correlation collector:

```bash
sudo -E python3 node_collector/main.py
```

Scripts:

```bash
python3 scripts/monitor_cpu_psi.py
python3 scripts/step_response_prober.py
python3 scripts/latency_p99_prober.py
```


## Docker

K-Sense requires privileged access for eBPF. Example:

```bash
docker build -t ksense .
docker run --rm --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /lib/modules:/lib/modules:ro \
  ksense
```

## Kubernetes

The DaemonSet runs one pod per node.

**Build and push the image first** (replace `<registry>` with your registry, e.g. `docker.io/myuser`):

```bash
docker build -t <registry>/ksense:latest .
docker push <registry>/ksense:latest
```

Then update the image reference in [kubernetes/daemonset.yaml](kubernetes/daemonset.yaml) to match, and apply:

```bash
kubectl apply -k kubernetes/
```

`kernel_metrics.csv` is generated inside the pod filesystem when running as a DaemonSet, under `/tmp/ksense/`.

Check status:

```bash
kubectl get ds -n ksense
kubectl get pods -n ksense -l app=ksense -o wide
```

## Research Context (IEEE Paper Summary)

K-Sense targets edge environments where applications are often black boxes and
application-level instrumentation is impractical. It relies on a small set of
kernel-level delay signals (CPU scheduling latency, SoftIRQ processing time, and
D-state I/O latency) and models the system state as a point in a multi-dimensional
feature space. The deviation from a calibrated baseline is quantified using the
Mahalanobis distance (friction), while a direction sign indicates whether the
system is above or below the baseline. An adaptive energy signal captures short-
term instability in friction.

The framework is evaluated with real workloads (DeathStarBench microservices and
a sentiment-analysis application). Results show that friction tracks application
P99 latency under changing load and remains informative when CPU utilization and
PSI saturate, enabling non-invasive QoS inference for admission control and
scheduling decisions.

## Citation

If you use K-Sense in your research, please cite our paper:

```bibtex
@inproceedings{ksense2026,
  author    = {Abdullah Muslim and Ali Beiti Aydenlou and Stephan Recker},
  title     = {K-Sense: A Non-Invasive eBPF Framework for QoS Inference},
  booktitle = {Proceedings of the IEEE International Conference on Fog and Edge Computing (ICFEC)},
  year      = {2026},
}
```

## Example Output

A sample [kernel_metrics_sample.csv](examples/kernel_metrics_sample.csv) is provided in `examples/`.
It shows the calibration phase (`CALIBRATING`), baseline freeze (`FROZEN`), and friction/energy
signals rising and falling in response to a load step.

## Notes

- `bcc` must be installed via the system package manager, not pip:
  `sudo apt-get install bpfcc-tools python3-bpfcc`
- Requires `numpy>=1.21` and `requests>=2.25` (`pip install -r requirements.txt`).
- Run with appropriate privileges for eBPF (typically `sudo`).
