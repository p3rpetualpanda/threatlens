from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from app import users


@pytest.fixture(autouse=True)
def _cheap_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    """Full-cost argon2 makes every test that creates a user slow; the algorithm is unchanged."""
    monkeypatch.setattr(users, "_hasher", PasswordHasher(time_cost=1, memory_cost=1024))
