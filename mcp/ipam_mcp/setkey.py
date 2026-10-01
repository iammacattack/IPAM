"""Store the MCP server's IPAM API key in Windows Credential Manager (never in a config file).

    Get-Clipboard | ipam-mcp-setkey      # easiest: copy the key, then pipe the clipboard in
    ipam-mcp-setkey                      # or paste at the hidden prompt (right-click to paste)
"""

from __future__ import annotations

import getpass
import re
import sys

import keyring

from .client import KEYRING_SERVICE, KEYRING_USER, Ipam, IpamError

KEY_RE = re.compile(r"ipam_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{32,}")


def read_key() -> str:
    if not sys.stdin.isatty():
        raw = sys.stdin.read()  # piped in, e.g. Get-Clipboard | ipam-mcp-setkey
    else:
        raw = getpass.getpass("Paste the IPAM API key (input hidden; right-click to paste if Ctrl+V does nothing), then Enter: ")
    # Tolerate quotes, spaces and line breaks around the key, or a whole 'IPAM_..._KEY=...' line.
    m = KEY_RE.search(raw or "")
    return m.group(0) if m else (raw or "").strip()


def main() -> int:
    key = read_key()
    if not key:
        print("Nothing came through. In some terminals Ctrl+V doesn't reach a hidden prompt.\n"
              "Copy the key, then run:  Get-Clipboard | ipam-mcp-setkey", file=sys.stderr)
        return 1
    if not KEY_RE.fullmatch(key):
        print("That doesn't look like an IPAM API key (ipam_<8 characters>_<secret>). Copy it again from the API keys page.", file=sys.stderr)
        return 1
    api = Ipam(key=key)
    try:
        me = api.get("/auth/me")
    except IpamError as err:
        print(f"IPAM refused the key: {err.describe()}", file=sys.stderr)
        return 1
    perms = set(me.get("permissions") or [])
    keyring.set_password(KEYRING_SERVICE, KEYRING_USER, key)
    print(f"Stored in Windows Credential Manager ({KEYRING_SERVICE}). IPAM at {api.base_url} accepted it (key {key.split('_')[1]}).")
    extra = sorted(perms - {"read"})
    if extra:
        print(f"Note: this key can also {', '.join(extra)}. The MCP tools only read, but a read-only key is safer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
