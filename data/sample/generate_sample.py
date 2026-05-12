"""
Synthetic CICIDS-2017 sample generator for CI/CD pipelines.

Generates a 1,000-row CSV with realistic feature distributions
so unit tests and model smoke tests can run without the full 8GB dataset.

Output: data/sample/cicids_sample.csv (gitignored)

Usage:
    python data/sample/generate_sample.py
    python data/sample/generate_sample.py --rows 5000 --seed 42
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import numpy as np
import pandas as pd

OUTPUT_PATH = Path(__file__).parent / "cicids_sample.csv"

# Class distribution mirrors CICIDS-2017 approximate proportions
CLASS_WEIGHTS = {
    "BENIGN": 0.775,
    "DDoS": 0.085,
    "PortScan": 0.065,
    "Bot": 0.030,
    "Web Attack": 0.020,
    "FTP-Patator": 0.010,
    "SSH-Patator": 0.008,
    "DoS Hulk": 0.005,
    "Heartbleed": 0.001,
    "Infiltration": 0.001,
}

# Feature generation parameters per class (mean, std multiplier)
# Realistic but synthetic — just enough to test model code paths
CLASS_FEATURE_PARAMS: dict[str, dict[str, tuple[float, float]]] = {
    "BENIGN": {"Flow Duration": (50000, 30000), "Total Fwd Packets": (5, 3)},
    "DDoS": {"Flow Duration": (1000, 500), "Total Fwd Packets": (1000, 200)},
    "PortScan": {"Flow Duration": (100, 50), "Total Fwd Packets": (1, 0.5)},
    "Bot": {"Flow Duration": (200000, 100000), "Total Fwd Packets": (20, 10)},
}


def _class_for_row(rng: np.random.Generator) -> str:
    labels = list(CLASS_WEIGHTS.keys())
    probs = list(CLASS_WEIGHTS.values())
    return rng.choice(labels, p=probs)  # type: ignore[return-value]


def generate_sample(n_rows: int = 1000, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    labels = [_class_for_row(rng) for _ in range(n_rows)]

    # All 78 numeric features — generated as abs(normal) to stay non-negative
    feature_data: dict[str, np.ndarray] = {}

    feature_names = [
        "Destination Port", "Flow Duration", "Total Fwd Packets",
        "Total Backward Packets", "Total Length of Fwd Packets",
        "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
        "Min Packet Length", "Max Packet Length", "Packet Length Mean",
        "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
        "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
        "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
        "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
        "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
        "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
        "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ]

    for feat in feature_names:
        feature_data[feat] = np.abs(rng.normal(loc=100.0, scale=50.0, size=n_rows))

    # Override a few key features with class-specific distributions
    for i, label in enumerate(labels):
        params = CLASS_FEATURE_PARAMS.get(label, {})
        for feat, (mean, std) in params.items():
            if feat in feature_data:
                feature_data[feat][i] = abs(rng.normal(mean, std))

    # Destination Port: integer in common port range
    feature_data["Destination Port"] = rng.integers(1, 65535, size=n_rows).astype(float)

    # Flag columns: binary integers
    for flag_col in ["FIN Flag Count", "SYN Flag Count", "RST Flag Count",
                     "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
                     "CWE Flag Count", "ECE Flag Count",
                     "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags"]:
        feature_data[flag_col] = rng.integers(0, 2, size=n_rows).astype(float)

    df = pd.DataFrame(feature_data)
    df["Label"] = labels  # CICIDS-2017 uses "Label" (with leading space stripped by normalizer)
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic CICIDS sample")
    parser.add_argument("--rows", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default=str(OUTPUT_PATH))
    args = parser.parse_args()

    df = generate_sample(args.rows, args.seed)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    counts = df["Label"].value_counts()
    print(f"Generated {len(df)} rows → {output}")
    print(counts.to_string())


if __name__ == "__main__":
    main()
