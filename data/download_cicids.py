"""
CICIDS-2017 Dataset Downloader

Downloads the CICIDS-2017 Intrusion Detection Evaluation Dataset from the
University of New Brunswick (UNB) into data/cicids/.

Dataset homepage: https://www.unb.ca/cic/datasets/ids-2017.html

The dataset consists of 5 days of network traffic (July 3-7, 2017):
  - Monday:    Benign traffic only (~11 classes: BENIGN)
  - Tuesday:   FTP-Patator, SSH-Patator (brute force)
  - Wednesday: DoS attacks (Slowloris, Slowhttptest, Hulk, GoldenEye, Heartbleed)
  - Thursday:  Web Attacks (Brute Force, XSS, SQL Injection), Infiltration
  - Friday:    Botnet, PortScan, DDoS

Total size: ~8GB (CSV format, CICFlowMeter extracted features)

Usage:
    python data/download_cicids.py                      # download all 5 days
    python data/download_cicids.py --day tuesday        # single day
    python data/download_cicids.py --list               # list available files
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from urllib.request import urlretrieve

# Note: The UNB dataset requires registration. The URLs below are the
# direct download links after registration. If these fail, visit
# https://www.unb.ca/cic/datasets/ids-2017.html to obtain current links.
DATASET_FILES = {
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

# MITRE ATT&CK STIX bundle (needed for mitre_mapper.py)
MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

OUTPUT_DIR = Path(__file__).parent / "cicids"
MITRE_OUTPUT = Path(__file__).parent / "enterprise-attack.json"


def _progress(block_num: int, block_size: int, total_size: int) -> None:
    downloaded = block_num * block_size
    if total_size > 0:
        pct = min(100, downloaded * 100 / total_size)
        mb_done = downloaded / 1024 / 1024
        mb_total = total_size / 1024 / 1024
        print(f"\r  {pct:5.1f}%  {mb_done:.0f} / {mb_total:.0f} MB", end="", flush=True)


def download_file(url: str, dest: Path, description: str = "") -> None:
    if dest.exists():
        size_mb = dest.stat().st_size / 1024 / 1024
        print(f"  Already downloaded: {dest.name} ({size_mb:.0f} MB)")
        return

    print(f"Downloading {description or dest.name}...")
    print(f"  URL: {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        urlretrieve(url, dest, reporthook=_progress)
        print()  # newline after progress
        size_mb = dest.stat().st_size / 1024 / 1024
        print(f"  Saved: {dest} ({size_mb:.1f} MB)")
    except Exception as e:
        print(f"\n  ERROR: {e}")
        if dest.exists():
            dest.unlink()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Download CICIDS-2017 dataset")
    parser.add_argument(
        "--day",
        choices=list(DATASET_FILES.keys()) + ["all"],
        default="all",
        help="Which day to download (default: all)",
    )
    parser.add_argument("--list", action="store_true", help="List available files and exit")
    parser.add_argument("--mitre", action="store_true", default=True,
                        help="Also download MITRE ATT&CK STIX bundle (default: True)")
    parser.add_argument("--no-mitre", dest="mitre", action="store_false")
    args = parser.parse_args()

    if args.list:
        print("Available CICIDS-2017 files:")
        for key, info in DATASET_FILES.items():
            status = "✓" if (OUTPUT_DIR / info["filename"]).exists() else " "
            print(f"  [{status}] {key:15s} — {info['description']}")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.day == "all":
        days_to_download = list(DATASET_FILES.keys())
    else:
        days_to_download = [args.day]

    for day in days_to_download:
        info = DATASET_FILES[day]
        dest = OUTPUT_DIR / info["filename"]
        download_file(info["url"], dest, info["description"])

    if args.mitre and not MITRE_OUTPUT.exists():
        print("\nDownloading MITRE ATT&CK STIX bundle (~12MB)...")
        download_file(MITRE_ATTACK_URL, MITRE_OUTPUT, "MITRE ATT&CK Enterprise")

    print("\nDone. Files saved to:", OUTPUT_DIR)
    print("Run 'python scripts/run_training.py' after downloading to train models.")


if __name__ == "__main__":
    main()
