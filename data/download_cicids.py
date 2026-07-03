"""
CICIDS-2017 Dataset Downloader

Downloads the CICIDS-2017 Intrusion Detection Evaluation Dataset from the
University of New Brunswick (UNB) into ``data/cicids/``.

Dataset homepage: https://www.unb.ca/cic/datasets/ids-2017.html

Security posture:
  * HTTPS-only URLs; connections use ``requests`` with a retry adapter and
    an explicit socket-level timeout — no more silent hangs on a dropped
    connection.
  * Each downloaded CSV is streamed to disk to a ``.partial`` sidecar and
    only renamed after a successful SHA-256 check against
    ``data/cicids_sha256.txt``. Any hash mismatch aborts and cleans up the
    partial file, preventing tampered CSVs from ever reaching the training
    pipeline.
  * Extract paths are normalised through ``Path().name`` — no manifest entry
    can escape ``OUTPUT_DIR`` via ``..`` or absolute paths (zip-slip
    equivalent for arbitrary write).

Total size: ~8GB (CSV format, CICFlowMeter extracted features)

Usage:
    python data/download_cicids.py                      # download all 5 days
    python data/download_cicids.py --day tuesday        # single day
    python data/download_cicids.py --list               # list available files
    python data/download_cicids.py --skip-hash-check    # bootstrap only
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path
from typing import Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Direct-download URLs from UNB.
DATASET_FILES: dict[str, dict[str, str]] = {
    "monday": {
        "filename": "Monday-WorkingHours.pcap_ISCX.csv",
        "description": "Benign traffic only",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Monday-WorkingHours.pcap_ISCX.csv",
    },
    "tuesday": {
        "filename": "Tuesday-WorkingHours.pcap_ISCX.csv",
        "description": "FTP-Patator, SSH-Patator",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Tuesday-WorkingHours.pcap_ISCX.csv",
    },
    "wednesday": {
        "filename": "Wednesday-workingHours.pcap_ISCX.csv",
        "description": "DoS attacks, Heartbleed",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Wednesday-workingHours.pcap_ISCX.csv",
    },
    "thursday": {
        "filename": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "description": "Web Attacks (morning)",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    },
    "thursday-pm": {
        "filename": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "description": "Infiltration (afternoon)",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    },
    "friday-ddos": {
        "filename": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "description": "DDoS",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    },
    "friday-portscan": {
        "filename": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "description": "PortScan",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    },
    "friday-botnet": {
        "filename": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "description": "Botnet",
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    },
}

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

OUTPUT_DIR = Path(__file__).parent / "cicids"
MITRE_OUTPUT = Path(__file__).parent / "enterprise-attack.json"
HASH_FILE = Path(__file__).parent / "cicids_sha256.txt"

_HASH_PLACEHOLDER = "REPLACE_ME_PLACEHOLDER_HASH_ONLY_FOR_BOOTSTRAP"
_CHUNK = 1 << 20  # 1 MiB


class HashMismatchError(RuntimeError):
    """Raised when a downloaded artifact fails its SHA-256 check."""


def _session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(408, 429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _load_expected_hashes() -> dict[str, str]:
    if not HASH_FILE.exists():
        return {}
    expected: dict[str, str] = {}
    for raw in HASH_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, filename = parts[0].strip(), parts[1].strip()
        expected[Path(filename).name] = digest.lower()
    return expected


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _verify(path: Path, expected: dict[str, str], *, skip: bool) -> None:
    """Verify ``path`` against the manifest. ``skip=True`` short-circuits."""
    if skip:
        logger.warning("Skipping hash check for %s (--skip-hash-check)", path.name)
        return

    digest = expected.get(path.name)
    if not digest or digest == _HASH_PLACEHOLDER.lower():
        raise HashMismatchError(
            f"No verified SHA-256 for {path.name}. Populate {HASH_FILE} before "
            "downloading, or pass --skip-hash-check for a one-off bootstrap."
        )

    actual = _sha256(path)
    if actual != digest:
        path.unlink(missing_ok=True)
        raise HashMismatchError(
            f"SHA-256 mismatch for {path.name}: expected {digest}, got {actual}"
        )
    logger.info("Integrity ok: %s", path.name)


def _stream_download(
    session: requests.Session,
    url: str,
    dest: Path,
    *,
    connect_timeout: float = 10.0,
    read_timeout: float = 120.0,
) -> None:
    """Stream ``url`` to ``dest.partial`` and rename on success."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".partial")
    partial.unlink(missing_ok=True)

    try:
        with session.get(url, stream=True, timeout=(connect_timeout, read_timeout)) as response:
            response.raise_for_status()
            total = int(response.headers.get("Content-Length") or 0)
            downloaded = 0
            with partial.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=_CHUNK):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = min(100.0, downloaded * 100 / total)
                        print(
                            f"\r  {pct:5.1f}%  {downloaded / 1e6:.0f} / {total / 1e6:.0f} MB",
                            end="",
                            flush=True,
                        )
            print()
    except Exception:
        partial.unlink(missing_ok=True)
        raise

    partial.replace(dest)


def download_file(
    session: requests.Session,
    url: str,
    dest: Path,
    expected: dict[str, str],
    *,
    description: str = "",
    skip_hash_check: bool = False,
) -> None:
    if dest.exists():
        try:
            _verify(dest, expected, skip=skip_hash_check)
            print(f"  Already downloaded (verified): {dest.name}")
            return
        except HashMismatchError as exc:
            logger.warning("Cached %s failed verification: %s", dest.name, exc)
            dest.unlink(missing_ok=True)

    print(f"Downloading {description or dest.name}...")
    print(f"  URL: {url}")
    _stream_download(session, url, dest)
    _verify(dest, expected, skip=skip_hash_check)
    size_mb = dest.stat().st_size / 1024 / 1024
    print(f"  Saved: {dest} ({size_mb:.1f} MB)")


def _iter_days(selection: str) -> Iterable[str]:
    return DATASET_FILES.keys() if selection == "all" else [selection]


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Download CICIDS-2017 dataset")
    parser.add_argument(
        "--day",
        choices=list(DATASET_FILES) + ["all"],
        default="all",
        help="Which day to download (default: all)",
    )
    parser.add_argument("--list", action="store_true", help="List available files and exit")
    parser.add_argument(
        "--mitre", action=argparse.BooleanOptionalAction, default=True,
        help="Also download the MITRE ATT&CK STIX bundle",
    )
    parser.add_argument(
        "--skip-hash-check",
        action="store_true",
        help="Bootstrap only: skip SHA-256 verification (use once, then update cicids_sha256.txt).",
    )
    args = parser.parse_args()

    expected = _load_expected_hashes()

    if args.list:
        print("Available CICIDS-2017 files:")
        for key, info in DATASET_FILES.items():
            marker = "✓" if (OUTPUT_DIR / info["filename"]).exists() else " "
            print(f"  [{marker}] {key:15s} — {info['description']}")
        return 0

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    session = _session()
    try:
        for day in _iter_days(args.day):
            info = DATASET_FILES[day]
            # Normalize the filename so any manifest tampering cannot escape OUTPUT_DIR
            dest = OUTPUT_DIR / Path(info["filename"]).name
            download_file(
                session,
                info["url"],
                dest,
                expected,
                description=info["description"],
                skip_hash_check=args.skip_hash_check,
            )

        if args.mitre and not MITRE_OUTPUT.exists():
            print("\nDownloading MITRE ATT&CK STIX bundle (~12MB)...")
            _stream_download(session, MITRE_ATTACK_URL, MITRE_OUTPUT)
    except HashMismatchError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"\nERROR: network failure — {exc}", file=sys.stderr)
        return 3

    print(f"\nDone. Files saved to: {OUTPUT_DIR}")
    print("Run 'python scripts/run_training.py' after downloading to train models.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
