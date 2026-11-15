"""Decode + IDS hattinin sentetik benchmark'i; sonuclari reports/ altina yazar."""

import csv
import json
import os
import platform
import sys
import time
from pathlib import Path
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.can_frame import CANFrame
from src.dbc_decoder import DBCDecoder, calc_crc8_sae_j1850
from src.can_ids import CANIntrusionDetectionEngine

CONFIG_PATH = str(ROOT / "config" / "can_signals.json")


def run_benchmark(trials: int = 5, frames_per_trial: int = 50000, warmup_frames: int = 2000):
    dbc = DBCDecoder(CONFIG_PATH)

    # Pre-generate diverse test frames
    f_speed = CANFrame(0x244, b"\x1D\x7E\x00\x00\x30\x39\x00\x00", 8)
    f_engine = CANFrame(0x180, b"\x1F\x40\x80\x28\x00\x00\x00\x00", 8)
    f_brake = CANFrame(0x200, b"\x07\xD0\x02\x00\x00\x00\x01\x1D", 8)
    f_unknown = CANFrame(0x6F1, b"\x02\x10\x03\x00\x00\x00\x00\x00", 8)
    test_batch = [f_speed, f_engine, f_brake, f_unknown]

    print("=" * 75)
    print("EMPIRICAL BENCHMARK: Automotive-CAN-IDS-Lab In-Process Pipeline")
    print(f"OS: {platform.system()} {platform.release()} | Python: {platform.python_version()} ({platform.machine()})")
    print(f"Trials: {trials} | Frames per trial: {frames_per_trial:,} | Warm-up: {warmup_frames:,}")
    print("Pipeline: Frame Ingestion -> DBC Decoding -> 6-Layer CAN IDS Inspection")
    print("NOTE: Evaluates CPU throughput in-memory; does NOT transmit over physical CAN transceiver.")
    print("=" * 75)

    # Warm-up phase
    print("Performing warm-up run...")
    ids_warm = CANIntrusionDetectionEngine(dbc)
    for i in range(warmup_frames):
        f = test_batch[i % 4]
        f.timestamp = 100.0 + (i * 0.001)
        ids_warm.process_frame(f, current_bus_load_pct=35.0)

    trial_results = []
    latencies_us_all = []
    process = psutil.Process()

    for trial_idx in range(1, trials + 1):
        ids = CANIntrusionDetectionEngine(dbc)
        latencies_ns = []
        total_alerts = 0

        t_start = time.perf_counter_ns()

        for i in range(frames_per_trial):
            f = test_batch[i % 4]
            f.timestamp = 1000.0 + (trial_idx * 100.0) + (i * 0.001)

            t0 = time.perf_counter_ns()
            alerts = ids.process_frame(f, current_bus_load_pct=35.0)
            t1 = time.perf_counter_ns()

            latencies_ns.append(t1 - t0)
            total_alerts += len(alerts)

        t_end = time.perf_counter_ns()
        total_time_sec = (t_end - t_start) / 1e9
        throughput = frames_per_trial / total_time_sec

        latencies_ns.sort()
        n = len(latencies_ns)
        p50 = latencies_ns[int(n * 0.50)] / 1000.0  # us
        p95 = latencies_ns[int(n * 0.95)] / 1000.0  # us
        p99 = latencies_ns[int(n * 0.99)] / 1000.0  # us
        mean_lat = (sum(latencies_ns) / n) / 1000.0

        latencies_us_all.extend([x / 1000.0 for x in latencies_ns])

        mem_mb = process.memory_info().rss / (1024 * 1024)

        trial_data = {
            "trial": trial_idx,
            "samples": frames_per_trial,
            "total_time_sec": round(total_time_sec, 4),
            "throughput_frames_per_sec": round(throughput, 1),
            "latency_p50_us": round(p50, 2),
            "latency_p95_us": round(p95, 2),
            "latency_p99_us": round(p99, 2),
            "latency_mean_us": round(mean_lat, 2),
            "memory_rss_mb": round(mem_mb, 2),
            "total_alerts": total_alerts
        }
        trial_results.append(trial_data)
        print(f"Trial {trial_idx}/{trials}: Throughput = {throughput:,.1f} frames/s | "
              f"p50 = {p50:.2f} \u00b5s | p95 = {p95:.2f} \u00b5s | p99 = {p99:.2f} \u00b5s | "
              f"RAM = {mem_mb:.1f} MB")

    # Aggregate Statistics
    avg_throughput = sum(t["throughput_frames_per_sec"] for t in trial_results) / trials
    latencies_us_all.sort()
    n_all = len(latencies_us_all)
    global_p50 = latencies_us_all[int(n_all * 0.50)]
    global_p95 = latencies_us_all[int(n_all * 0.95)]
    global_p99 = latencies_us_all[int(n_all * 0.99)]
    global_mean = sum(latencies_us_all) / n_all
    final_rss = trial_results[-1]["memory_rss_mb"]

    summary = {
        "project": "Automotive-CAN-IDS-Lab",
        "benchmark_type": "synthetic_in_process_pipeline",
        "scope_description": "In-memory CAN frame object generation, DBC signal decoding and 6-layer IDS rule verification without physical SocketCAN or hardware bus transceivers",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": {
            "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
            "cpu": platform.processor(),
            "machine": platform.machine()
        },
        "config": {
            "trials": trials,
            "samples_per_trial": frames_per_trial,
            "warmup_frames": warmup_frames,
            "total_samples_evaluated": trials * frames_per_trial
        },
        "results": {
            "average_throughput_frames_per_sec": round(avg_throughput, 1),
            "global_latency_p50_us": round(global_p50, 2),
            "global_latency_p95_us": round(global_p95, 2),
            "global_latency_p99_us": round(global_p99, 2),
            "global_latency_mean_us": round(global_mean, 2),
            "final_memory_rss_mb": final_rss
        },
        "comparability_notes": (
            "Measures in-process Python CPU execution. Physical 500 kbps CAN bus throughput is fundamentally "
            "governed by bit timing, bit stuffing overhead, inter-frame spacing, and physical bus arbitration, "
            "typically limiting maximum theoretical line rate to ~4,000 standard 8-byte frames/second."
        ),
        "trials": trial_results
    }

    out_dir = ROOT / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Export benchmark_summary.json
    summary_path = out_dir / "benchmark_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Export benchmark_runs.csv
    csv_path = out_dir / "benchmark_runs.csv"
    csv_fields = [
        "trial", "samples", "total_time_sec", "throughput_frames_per_sec",
        "latency_p50_us", "latency_p95_us", "latency_p99_us", "latency_mean_us", "memory_rss_mb", "total_alerts"
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        writer.writeheader()
        for t in trial_results:
            writer.writerow(t)

    print("=" * 75)
    print(f"OVERALL RESULTS ({trials} trials, {trials * frames_per_trial:,} frames):")
    print(f"Average Throughput: {avg_throughput:,.1f} frames/second")
    print(f"Latency p50:        {global_p50:.2f} \u00b5s")
    print(f"Latency p95:        {global_p95:.2f} \u00b5s")
    print(f"Latency p99:        {global_p99:.2f} \u00b5s")
    print(f"Final Memory RSS:   {final_rss} MB")
    print(f"Summary JSON saved: {summary_path}")
    print(f"Runs CSV saved:     {csv_path}")
    print("=" * 75)


if __name__ == "__main__":
    run_benchmark(trials=5, frames_per_trial=50000, warmup_frames=2000)
