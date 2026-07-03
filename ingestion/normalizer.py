"""
CICIDS-2017 normalization — the most critical Phase 1 file.

Known dataset issues handled here:
  1. All column headers have leading/trailing spaces (" Label", " Flow Duration", etc.)
  2. "Infinity" and "-Infinity" values in "Flow Bytes/s" and "Flow Packets/s"
  3. NaN values — imputed with column median (not mean: distributions are heavily skewed)
  4. Mixed dtypes across 2.8M rows — requires low_memory=False

Two label mappings are exposed:

  ``LABEL_TO_FINE_INT`` — preserves attack granularity (XSS ≠ SQLi ≠ Brute Force).
      Use this for training the classifier and for SHAP/MITRE mapping.
  ``FINE_TO_COARSE_INT`` — rolls fine classes up into 9 reporting buckets.
      Use this for dashboards and executive reports where noise matters more
      than root-cause detail.

``LABEL_TO_INT`` / ``INT_TO_LABEL`` are kept for backwards compatibility with
call sites that already round-trip through the coarse map.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
from pydantic import ValidationError

from ingestion.schemas.cicids_schema import CICIDSRecord

logger = logging.getLogger(__name__)

# Columns known to contain Infinity values in CICIDS-2017
_INFINITY_COLUMNS = ("Flow Bytes/s", "Flow Packets/s")

# ── Label mappings ────────────────────────────────────────────────────
# Fine map preserves subtype granularity (13 classes).
LABEL_TO_FINE_INT: dict[str, int] = {
    "BENIGN": 0,
    "DDoS": 1,
    "PortScan": 2,
    "Bot": 3,
    "Infiltration": 4,
    "Web Attack \x96 Brute Force": 5,
    "Web Attack \x96 XSS": 6,
    "Web Attack \x96 Sql Injection": 7,
    "FTP-Patator": 8,
    "SSH-Patator": 9,
    "DoS slowloris": 10,
    "DoS Slowhttptest": 11,
    "DoS Hulk": 12,
    "DoS GoldenEye": 13,
    "Heartbleed": 14,
}

# Coarse rollup for reporting (9 buckets).
FINE_TO_COARSE_INT: dict[int, int] = {
    0: 0,   # BENIGN
    1: 1,   # DDoS
    2: 2,   # PortScan
    3: 3,   # Botnet
    4: 4,   # Infiltration
    5: 5, 6: 5, 7: 5,   # Web Attack (BF / XSS / SQLi)
    8: 6, 9: 6,          # Brute Force (FTP / SSH)
    10: 7, 11: 7, 12: 7, 13: 7,  # DoS variants
    14: 8,  # Heartbleed
}

INT_TO_LABEL: dict[int, str] = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan",
    3: "Botnet",
    4: "Infiltration",
    5: "Web Attack",
    6: "Brute Force",
    7: "DoS",
    8: "Heartbleed",
}

# Coarse map kept for callers that don't need subtype detail.
LABEL_TO_INT: dict[str, int] = {
    lbl: FINE_TO_COARSE_INT[fine] for lbl, fine in LABEL_TO_FINE_INT.items()
}


# ── Shared cleaners ───────────────────────────────────────────────────

def clean_infinities(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce Infinity strings/floats to NaN across all numeric columns.

    Idempotent. Safe to call on both full frames and streamed chunks.
    """
    for col in _INFINITY_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols):
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    return df


def normalize_headers(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from headers and normalise the label column to lower case."""
    df.columns = df.columns.str.strip()
    if "Label" in df.columns:
        df.rename(columns={"Label": "label"}, inplace=True)
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()
    return df


# ── Loaders ───────────────────────────────────────────────────────────

def load_csv(path: str | Path) -> pd.DataFrame:
    """Load a CICIDS-2017 CSV, strip header spaces, and replace Infinity values."""
    df = pd.read_csv(path, low_memory=False)
    df = normalize_headers(df)
    df = clean_infinities(df)
    logger.info("Loaded %d rows from %s", len(df), path)
    return df


def impute_medians(df: pd.DataFrame) -> pd.DataFrame:
    """Fill NaN values with column medians (robust to skewed distributions)."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols):
        medians = df[numeric_cols].median()
        df[numeric_cols] = df[numeric_cols].fillna(medians)
    return df


def _normalise_label(label: str) -> str:
    """Normalise the unicode dash variants seen in Web Attack labels."""
    return label.replace("–", "\x96").replace("—", "\x96")


def normalize_labels(df: pd.DataFrame, *, fine: bool = False) -> pd.DataFrame:
    """Map CICIDS string labels to integer classes.

    ``fine=True`` preserves attack subtypes (14 classes). Default is the
    coarse 9-class rollup.
    """
    if "label" not in df.columns:
        return df

    table = LABEL_TO_FINE_INT if fine else LABEL_TO_INT

    def _map(label: str) -> int:
        return table.get(_normalise_label(label), table.get(label, -1))

    column = "label_fine_int" if fine else "label_int"
    df[column] = df["label"].apply(_map)

    unknown = df.loc[df[column] == -1, "label"].unique()
    if len(unknown):
        logger.warning("Unknown labels (mapped to -1): %s", unknown.tolist())

    return df


def validate_batch(records: list[dict]) -> tuple[list[CICIDSRecord], list[dict]]:
    """Validate a list of row dicts against ``CICIDSRecord``.

    Returns ``(valid_records, failed_rows)``.
    """
    valid, failed = [], []
    for row in records:
        try:
            valid.append(CICIDSRecord.model_validate(row))
        except ValidationError as e:
            logger.debug("Validation failed for row: %s", e)
            failed.append(row)
    return valid, failed


def iter_chunks(
    path: str | Path,
    chunk_size: int = 10_000,
) -> Iterator[pd.DataFrame]:
    """Yield normalised DataFrame chunks — memory-efficient for the 2.8M-row set."""
    for chunk in pd.read_csv(path, low_memory=False, chunksize=chunk_size):
        chunk = normalize_headers(chunk)
        chunk = clean_infinities(chunk)
        yield chunk


def process_file(path: str | Path, *, fine: bool = False) -> pd.DataFrame:
    """Full normalization pipeline for a single CICIDS CSV file."""
    df = load_csv(path)
    df = impute_medians(df)
    df = normalize_labels(df, fine=fine)
    return df
