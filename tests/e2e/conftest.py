"""End-to-end fixtures: run against the live Compose stack (docker compose --profile test run --rm tests)."""

from __future__ import annotations

import copy
import os
import uuid
from pathlib import Path

import psycopg
import pytest
import yaml

from helpers import API_KEY, DATABASE_URL, make_client

SEED = Path(__file__).resolve().parents[2] / "seed"


def pytest_collection_modifyitems(config, items):
    if not API_KEY:
        skip = pytest.mark.skip(reason="IPAM_API_KEY not set; run via the Compose test profile")
        for item in items:
            if "e2e" in str(item.fspath):
                item.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def reset_allocations():
    """Clear site allocations so the reference workflows (X9 etc.) are repeatable.

    Only runs when IPAM_TEST_RESET=1, which the Compose test profile sets. Templates,
    the VLAN library and the audit log are left alone.
    """
    if os.environ.get("IPAM_TEST_RESET") == "1" and DATABASE_URL and API_KEY:
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute("TRUNCATE ip_record, subnet, block, site, site_code CASCADE")
    yield


@pytest.fixture(scope="session")
def api():
    with make_client(key=API_KEY) as c:
        yield c


@pytest.fixture(scope="session")
def anon():
    with make_client("pytest/anon") as c:
        yield c


@pytest.fixture(scope="session")
def db():
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        yield conn


@pytest.fixture
def example_content() -> dict:
    doc = yaml.safe_load((SEED / "templates" / "EXAMPLE-NET-10.yaml").read_text(encoding="utf-8"))
    return copy.deepcopy(doc["content"])


@pytest.fixture
def unique() -> str:
    return uuid.uuid4().hex[:6].upper()


def octets(cidr: str) -> tuple[str, str]:
    a, b = cidr.split(".")[:2]
    return a, b
