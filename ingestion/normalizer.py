"""
CICIDS-2017 normalization — the most critical Phase 1 file.

Known dataset issues handled here:
  1. All column headers have leading/trailing spaces (" Label", " Flow Duration", etc.)
  2. "Infinity" and "-Infinity" values in "Flow Bytes/s" and "Flow Packets/s"
  3. NaN values — imputed with column median (not mean: distributions are heavily skewed)
  4. Mixed dtypes across 2.8M rows — requires low_memory=False
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

# Columns that are known to contain Infinity values in CICIDS-2017
_INFINITY_COLUMNS = ["Flow Bytes/s", "Flow Packets/s"]

# Map CICIDS-2017 string labels to integer class indices
LABEL_TO_INT: dict[str, int] = {
    "BENIGN": 0,
    "DDoS": 1,
    "PortScan": 2,
    "Bot": 3,
    "Infiltration": 4,
    "Web Attack \x96 Brute Force": 5,
    "Web Attack \x96 XSS": 5,
    "Web Attack \x96 Sql Injection": 5,
    "FTP-Patator": 6,
    "SSH-Patator": 6,
    "DoS slowloris": 7,
    "DoS Slowhttptest": 7,
    "DoS Hulk": 7,
    "DoS GoldenEye": 7,
    "Heartbleed": 8,
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


def load_csv(path: str | Path) -> pd.DataFrame:
    """Load a CICIDS-2017 CSV, strip header spaces, and replace Infinity values."""
    df = pd.read_csv(path, low_memory=False)

    # Fix 1: Strip leading/trailing spaces from all column names
    df.columns = df.columns.str.strip()

    # Fix 2: Replace Infinity strings with NaN in known columns
    for col in _INFINITY_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)

    # Fix 3: Replace any remaining Inf values across all numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # Fix 4: Strip spaces from the label column value
    if "Label" in df.columns:
        df.rename(columns={"Label": "label"}, inplace=True)
    if "label" in df.columns:
        df["label"] = df["label"].str.strip()

    logger.info("Loaded %d rows from %s", len(df), path)
    return df


def impute_medians(df: pd.DataFrame) -> pd.DataFrame:
    """Fill NaN values with column medians (robust to skewed distributions)."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    medians = df[numeric_cols].median()
    df[numeric_cols] = df[numeric_cols].fillna(medians)
    return df


def normalize_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map CICIDS string labels to consolidated integer classes."""
    if "label" not in df.columns:
        return df

    def _map(label: str) -> int:
        # Handle unicode dash variants in Web Attack labels
        normalized = label.replace("–", "\x96").replace("—", "\x96")
        return LABEL_TO_INT.get(normalized, LABEL_TO_INT.get(label, -1))

    df["label_int"] = df["label"].apply(_map)
    unknown = df[df["label_int"] == -1]["label"].unique()
    if len(unknown) > 0:
        logger.warning("Unknown labels (mapped to -1): %s", unknown.tolist())

    return df


def validate_batch(records: list[dict]) -> tuple[list[CICIDSRecord], list[dict]]:
    """
    Validate a list of row dicts against CICIDSRecord schema.
    Returns (valid_records, failed_rows).
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
    """
    Yield normalized DataFrame chunks from a CICIDS CSV.
    Use this for memory-efficient processing of the 2.8M-row dataset.
    """
    for chunk in pd.read_csv(path, low_memory=False, chunksize=chunk_size):
        chunk.columns = chunk.columns.str.strip()

        for col in _INFINITY_COLUMNS:
            if col in chunk.columns:
                chunk[col] = pd.to_numeric(chunk[col], errors="coerce")
                chunk[col] = chunk[col].replace([np.inf, -np.inf], np.nan)

        numeric_cols = chunk.select_dtypes(include=[np.number]).columns
        chunk[numeric_cols] = chunk[numeric_cols].replace([np.inf, -np.inf], np.nan)

        if "Label" in chunk.columns:
            chunk.rename(columns={"Label": "label"}, inplace=True)
        if "label" in chunk.columns:
            chunk["label"] = chunk["label"].str.strip()

        yield chunk


def process_file(path: str | Path) -> pd.DataFrame:
    """Full normalization pipeline for a single CICIDS CSV file."""
    df = load_csv(path)
    df = impute_medians(df)
    df = normalize_labels(df)
    return df
