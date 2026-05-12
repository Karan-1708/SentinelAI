#!/usr/bin/env python
"""
CLI entry point for model training.
Delegates to models/trainer.py.

Usage:
    python scripts/run_training.py
    python scripts/run_training.py --max-rows 50000  # quick sanity check
    python scripts/run_training.py --data-dir data/cicids --mlflow-uri http://localhost:5000
"""

import sys
from pathlib import Path

# Add project root so imports work from scripts/ directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.trainer import main

if __name__ == "__main__":
    main()
