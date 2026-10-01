"""Store the MCP server's IPAM API key in Windows Credential Manager (never in a config file).

    ipam-mcp-setkey            # prompts for the key, checks it against IPAM, stores it
"""

from __future__ import annotations

import getpass
import sys

import keyring

from .client import KEYRING_SERVICE, KEYRING_USER, Ipam, IpamError


def main() -> int:
    key = getpass.getpass("Paste the IPAM API key for the MCP server (input hidden): ").strip()
    if not key.startswith("ipam_"):
        print("That doesn't look like an IPAM API key (ipam_<prefix>_<secret>).", file=sys.stderr)
        return 1
    api = Ipam(key=key)
    try:
        me = api.get("/auth/me")
    except IpamError as err:
        print(f"IPAM refused the key: {err.describe()}", file=sys.stderr)
        return 1
    perms = set(me.get("permissions") or [])
    keyring.set_password(KEYRING_SERVICE, KEYRING_USER, key)
    print(f"Stored in Windows Credential Manager ({KEYRING_SERVICE}). IPAM at {api.base_url} accepted it.")
    extra = sorted(perms - {"read"})
    if extra:
        print(f"Note: this key can also {', '.join(extra)}. The MCP tools only read, but a read-only key is safer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
