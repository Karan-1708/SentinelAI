"""Unit tests for ingestion/normalizer.py — no Docker or dataset required."""

import io
import textwrap

import numpy as np
import pandas as pd
import pytest

from ingestion.normalizer import (
    LABEL_TO_INT,
    impute_medians,
    load_csv,
    normalize_labels,
    process_file,
    validate_batch,
)


@pytest.fixture
def dirty_csv(tmp_path):
    """A minimal CSV mimicking CICIDS-2017's dirty formatting."""
    content = textwrap.dedent("""\
         Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length.1, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
        80,100000,10,5,1000,500,200,10,100,50,100,10,50,25,Infinity,100,50000,10000,100000,1000,50000,5000,10000,100000,1000,50000,5000,10000,100000,1000,0,0,0,0,200,100,100,50,10,200,100,50,2500,0,1,0,1,5,0,0,0,1,100,100,50,200,0,0,0,0,0,0,10,1000,5,500,65535,1024,9,20,0,0,0,0,0,0,0,0, BENIGN
        443,200000,20,10,2000,1000,400,20,200,100,200,20,100,50,Infinity,-Infinity,100000,20000,200000,2000,100000,10000,20000,200000,2000,100000,10000,20000,200000,2000,0,0,0,0,400,200,200,100,20,400,200,100,10000,0,2,0,2,10,0,0,0,2,200,200,100,400,0,0,0,0,0,0,20,2000,10,1000,65535,2048,18,20,0,0,0,0,0,0,0,0, DDoS
    """)
    p = tmp_path / "test.csv"
    p.write_text(content)
    return str(p)


def test_header_stripping(dirty_csv):
    """Column names must have no leading/trailing spaces after load."""
    df = load_csv(dirty_csv)
    for col in df.columns:
        assert col == col.strip(), f"Column '{col}' has whitespace"


def test_infinity_replaced_with_nan(dirty_csv):
    """Infinity values in Flow Bytes/s must become NaN, not remain as strings."""
    df = load_csv(dirty_csv)
    assert "Flow Bytes/s" in df.columns
    assert not any(df["Flow Bytes/s"].isin(["Infinity", "-Infinity"]))
    # No infinite floats either
    numeric = pd.to_numeric(df["Flow Bytes/s"], errors="coerce")
    assert not np.isinf(numeric.dropna()).any()


def test_label_normalized(dirty_csv):
    """Label values must be stripped of whitespace."""
    df = load_csv(dirty_csv)
    assert "label" in df.columns
    for val in df["label"]:
        assert val == val.strip()


def test_impute_medians_no_nan():
    """After imputation, no NaN should remain in numeric columns."""
    df = pd.DataFrame({
        "a": [1.0, np.nan, 3.0],
        "b": [np.nan, np.nan, 6.0],
        "label": ["BENIGN", "DDoS", "BENIGN"],
    })
    result = impute_medians(df)
    numeric = result.select_dtypes(include=[np.number])
    assert not numeric.isna().any().any()


def test_normalize_labels_known():
    """Known CICIDS labels must map to valid non-negative integers."""
    df = pd.DataFrame({"label": ["BENIGN", "DDoS", "PortScan"]})
    result = normalize_labels(df)
    assert (result["label_int"] >= 0).all()
    assert result.loc[result["label"] == "BENIGN", "label_int"].iloc[0] == LABEL_TO_INT["BENIGN"]


def test_normalize_labels_unknown():
    """Unknown labels must map to -1 (not raise)."""
    df = pd.DataFrame({"label": ["UNKNOWN_ATTACK"]})
    result = normalize_labels(df)
    assert result["label_int"].iloc[0] == -1


def test_validate_batch_rejects_bad_rows():
    """validate_batch must separate valid rows from rows missing required fields."""
    good_row = {
        "Destination Port": 80,
        "Flow Duration": 100000.0,
        "label": "BENIGN",
        # Minimal required fields — fill rest with 0
        **{k: 0 for k in [
            "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Max", "Fwd Packet Length Min",
            "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Bwd Packet Length Max", "Bwd Packet Length Min",
            "Bwd Packet Length Mean", "Bwd Packet Length Std",
            "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
            "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
            "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
            "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
            "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
            "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
            "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
            "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
            "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
            "Avg Bwd Segment Size", "Fwd Header Length.1", "Subflow Fwd Packets",
            "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
            "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
            "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
        ]},
    }
    bad_row = {"label": "BENIGN"}  # missing all required numeric fields

    valid, failed = validate_batch([good_row, bad_row])
    assert len(valid) == 1
    assert len(failed) == 1
