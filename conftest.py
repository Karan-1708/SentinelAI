"""Repo-wide pytest fixtures.

Global RNG seeding autouse fixture keeps every random operation deterministic
across tests. If a specific test needs stochastic behaviour it can explicitly
create its own generator.
"""

from __future__ import annotations

import random

import numpy as np
import pytest


@pytest.fixture(autouse=True)
def _global_deterministic_seed():
    random.seed(0)
    np.random.seed(0)
    yield
