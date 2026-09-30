from __future__ import annotations

from pathlib import Path

import pytest
import yaml

SEED = Path(__file__).resolve().parents[2] / "seed"


@pytest.fixture
def example_net_10() -> dict:
    return yaml.safe_load((SEED / "templates" / "EXAMPLE-NET-10.yaml").read_text(encoding="utf-8"))["content"]


@pytest.fixture
def host_roles() -> list[dict]:
    return yaml.safe_load((SEED / "host-roles.yaml").read_text(encoding="utf-8"))["hostRoles"]
