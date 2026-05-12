"""
Integration test: full PDF report round-trip.
Requires: trained model artifacts in models/ directory.

Run with:
    pytest tests/integration/test_report_generation.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))


@pytest.mark.integration
def test_pdf_report_generates_non_empty_bytes():
    """Generated PDF must be non-zero bytes and start with %PDF."""
    from explainability.report_generator import IncidentReportGenerator

    generator = IncidentReportGenerator()
    pdf_bytes = generator.generate(
        incident={
            "id": "00000000-0000-0000-0000-000000000001",
            "created_at": None,
            "severity": "HIGH",
            "threat_label": "DDoS",
            "confidence": 0.92,
            "anomaly_score": -0.28,
            "source_ip": "198.51.100.7",
            "dest_ip": "192.168.1.10",
        },
        shap_data={
            "feature_contributions": [
                {"feature": f"feature_{i}", "shap_value": (i - 5) * 0.1, "feature_value": float(i * 10)}
                for i in range(15)
            ]
        },
        mitre_data=[
            {
                "technique_id": "T1498",
                "technique_name": "Network DoS",
                "tactic": "impact",
                "url": "https://attack.mitre.org/techniques/T1498",
            }
        ],
    )

    assert len(pdf_bytes) > 0, "PDF must not be empty"
    assert pdf_bytes[:4] == b"%PDF", "Output must be a valid PDF"


@pytest.mark.integration
def test_pdf_report_benign():
    """BENIGN incidents must still generate a valid PDF (INFO severity)."""
    from explainability.report_generator import IncidentReportGenerator

    generator = IncidentReportGenerator()
    pdf_bytes = generator.generate(
        incident={
            "id": "00000000-0000-0000-0000-000000000002",
            "created_at": None,
            "severity": "INFO",
            "threat_label": "BENIGN",
            "confidence": 0.99,
            "anomaly_score": 0.15,
            "source_ip": None,
            "dest_ip": None,
        },
        shap_data={"feature_contributions": []},
        mitre_data=[],
    )

    assert pdf_bytes[:4] == b"%PDF"
