"""Shared settings and client factory for the end-to-end suite."""

from __future__ import annotations

import os

import httpx

BASE_URL = os.environ.get("IPAM_BASE_URL", "http://127.0.0.1:8820/api/v1")
API_KEY = os.environ.get("IPAM_API_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL")


def make_client(client_name: str = "pytest/e2e", key: str | None = None) -> httpx.Client:
    headers = {"X-Client-Name": client_name}
    if key is not None:
        headers["X-API-Key"] = key
    return httpx.Client(base_url=BASE_URL, headers=headers, timeout=30)
