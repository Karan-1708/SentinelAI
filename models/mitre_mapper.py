"""
MITRE ATT&CK TTP mapper.

Maps CICIDS-2017 threat labels to MITRE ATT&CK techniques and tactics
using the official mitreattack-python library (STIX 2.0).

The enterprise-attack.json STIX bundle is downloaded by:
    python data/download_cicids.py --mitre

The label → technique mapping is hardcoded because CICIDS-2017 has a fixed
set of attack categories that correspond directly to well-known TTPs.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_STIX_PATH = Path("data/enterprise-attack.json")

# CICIDS-2017 label → list of MITRE ATT&CK technique IDs
LABEL_TO_TECHNIQUES: dict[str, list[str]] = {
    "DDoS":         ["T1498", "T1499"],      # Network DoS, Endpoint DoS
    "PortScan":     ["T1046"],               # Network Service Discovery
    "FTP-Patator":  ["T1110.001"],           # Brute Force: Password Guessing
    "SSH-Patator":  ["T1110.001"],           # Brute Force: Password Guessing
    "Brute Force":  ["T1110.001", "T1110"],  # Brute Force
    "Botnet":       ["T1071", "T1090"],      # Application Layer Protocol, Proxy
    "Bot":          ["T1071", "T1090"],
    "Web Attack":   ["T1190", "T1059.007"], # Exploit Public-Facing App, JS
    "Infiltration": ["T1055"],               # Process Injection
    "Heartbleed":   ["T1040"],               # Network Sniffing
    "DoS":          ["T1499", "T1498"],      # Endpoint DoS, Network DoS
    "DoS Hulk":     ["T1499"],
    "DoS slowloris": ["T1499"],
    "BENIGN":       [],                      # No techniques for benign traffic
}


class MitreMapper:
    def __init__(self, stix_path: str | Path = DEFAULT_STIX_PATH) -> None:
        self._data = None
        self._stix_path = Path(stix_path)

    def _load(self) -> None:
        """Lazy-load the STIX data (avoids slow import at module level)."""
        if self._data is not None:
            return
        if not self._stix_path.exists():
            logger.warning(
                "MITRE ATT&CK STIX file not found at %s. "
                "Run: python data/download_cicids.py --mitre",
                self._stix_path,
            )
            self._data = None
            return
        try:
            from mitreattack.stix20 import MitreAttackData
            self._data = MitreAttackData(str(self._stix_path))
            logger.info("Loaded MITRE ATT&CK STIX data from %s", self._stix_path)
        except ImportError:
            logger.error("mitreattack-python not installed. pip install mitreattack-python")
            self._data = None

    def _resolve_technique(self, technique_id: str) -> dict:
        """Resolve a technique ID to its name and tactic via STIX data."""
        if self._data is None:
            return {
                "technique_id": technique_id,
                "technique_name": technique_id,
                "tactic": "unknown",
                "stix_id": None,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            }
        try:
            technique = self._data.get_object_by_attack_id(technique_id, "technique")
            if technique is None or getattr(technique, "revoked", False):
                return {
                    "technique_id": technique_id,
                    "technique_name": technique_id,
                    "tactic": "unknown",
                    "stix_id": None,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
                }
            tactic = (
                technique.kill_chain_phases[0].phase_name
                if technique.kill_chain_phases
                else "unknown"
            )
            return {
                "technique_id": technique_id,
                "technique_name": technique.name,
                "tactic": tactic,
                "stix_id": technique.id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            }
        except Exception as e:
            logger.debug("Failed to resolve technique %s: %s", technique_id, e)
            return {
                "technique_id": technique_id,
                "technique_name": technique_id,
                "tactic": "unknown",
                "stix_id": None,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            }

    def map(self, label: str) -> list[dict]:
        """
        Map a CICIDS-2017 threat label to MITRE ATT&CK techniques.

        Returns a list of dicts with keys:
            technique_id, technique_name, tactic, stix_id, url
        """
        self._load()
        technique_ids = LABEL_TO_TECHNIQUES.get(label, [])
        if not technique_ids:
            # Try fuzzy match on label prefix
            for known_label, ids in LABEL_TO_TECHNIQUES.items():
                if label.startswith(known_label) or known_label in label:
                    technique_ids = ids
                    break
        return [self._resolve_technique(tid) for tid in technique_ids]

    def get_tactic_for_label(self, label: str) -> str:
        """Return the primary tactic name for a label (for badge display)."""
        techniques = self.map(label)
        if not techniques:
            return "unknown"
        return techniques[0]["tactic"]
