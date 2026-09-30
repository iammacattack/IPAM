"""Start-up: apply migrations, load seed data, register the development key.

Seed loading is insert-if-absent, so anything an administrator changes through
the API survives a restart. Seed data is configuration (spec §16.3).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from psycopg.types.json import Jsonb

from .auth import ensure_bootstrap_key
from .config import settings
from .db import tx
from .security import SYSTEM_ROLES, hash_password
from .services import templates as tsvc

log = logging.getLogger("ipam.bootstrap")


def migrate() -> list[str]:
    applied: list[str] = []
    with tx() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('ipam:migrate'))")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        for path in sorted(Path(settings.migrations_dir).glob("*.sql")):
            if path.stem in done:
                continue
            conn.execute(path.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.stem,))
            applied.append(path.stem)
    return applied


def _load(name: str) -> dict[str, Any]:
    path = Path(settings.seed_dir) / name
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}


def seed() -> dict[str, int]:
    counts = {"vrfs": 0, "pools": 0, "vlans": 0, "hostRoles": 0, "templates": 0}
    pools_doc = _load("pools.yaml")
    with tx() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('ipam:seed'))")
        for v in pools_doc.get("vrfs", []):
            cur = conn.execute(
                "INSERT INTO vrf (vrf_key, description) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (v["vrfKey"], v.get("description")),
            )
            counts["vrfs"] += cur.rowcount
        for p in pools_doc.get("pools", []):
            cur = conn.execute(
                """INSERT INTO pool (pool_key, parent_key, vrf_key, allocation_prefix_length, strategy, uniqueness, description)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                (p["poolKey"], p.get("parentPool"), p["vrf"], p.get("allocationPrefixLength"),
                 p.get("strategy", "first-fit"), p.get("uniqueness", "enterprise"), p.get("description")),
            )
            if cur.rowcount:
                counts["pools"] += 1
                for i, cidr in enumerate(p.get("prefixes", [])):
                    conn.execute("INSERT INTO pool_prefix (pool_key, cidr, position) VALUES (%s, %s, %s)", (p["poolKey"], cidr, i))
                for cidr in p.get("exclusions", []):
                    conn.execute("INSERT INTO pool_exclusion (pool_key, cidr) VALUES (%s, %s)", (p["poolKey"], cidr))
        for k, v in (pools_doc.get("settings") or {}).items():
            conn.execute("INSERT INTO setting (key, value) VALUES (%s, %s) ON CONFLICT DO NOTHING", (k, Jsonb(v)))

        for v in _load("vlans.yaml").get("vlans", []):
            cur = conn.execute(
                """INSERT INTO vlan (vlan_key, vlan_id, vlan_name, class, security_zone, description)
                   VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                (v["vlanKey"], v.get("vlanId"), v["vlanName"], v.get("class"), v.get("securityZone"), v.get("description")),
            )
            if cur.rowcount:
                counts["vlans"] += 1
                for alias in v.get("aliases", []):
                    conn.execute("INSERT INTO vlan_alias (alias, vlan_key) VALUES (%s, %s) ON CONFLICT DO NOTHING", (alias, v["vlanKey"]))

        for r in _load("host-roles.yaml").get("hostRoles", []):
            cur = conn.execute(
                """INSERT INTO host_role (role_code, name, vlan_keys, hostname_pattern, offset_mode)
                   VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                (r["roleCode"], r.get("name"), r.get("vlanKeys", []), r.get("hostnamePattern"), r.get("offsetMode", "literalOctet")),
            )
            if cur.rowcount:
                counts["hostRoles"] += 1
                for i, m in enumerate(r.get("members", [])):
                    conn.execute(
                        """INSERT INTO host_role_member (role_code, name, ordinal, kind, host_position, secondary_host_octet, range_start, range_end)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                        (r["roleCode"], m["name"], i, m.get("kind", "fixed"), m.get("hostPosition"),
                         m.get("secondaryHostOctet"), m.get("rangeStart"), m.get("rangeEnd")),
                    )

        for path in sorted((Path(settings.seed_dir) / "templates").glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            key = doc["templateKey"]
            if conn.execute("SELECT 1 FROM template WHERE template_key = %s", (key,)).fetchone():
                continue
            conn.execute(
                "INSERT INTO template (template_key, description, created_by) VALUES (%s, %s, 'seed')",
                (key, doc.get("description")),
            )
            row, _ = tsvc.create_version(conn, key, doc["content"], "seed")
            rel = doc.get("release")
            if rel:
                tsvc.release(conn, key, row["version"], rel.get("notes"), rel.get("evidence"), "seed")
            counts["templates"] += 1

        if settings.bootstrap_api_key:
            ensure_bootstrap_key(conn, settings.bootstrap_api_key)
        else:
            log.warning("IPAM_BOOTSTRAP_API_KEY isn't set; no API key is registered for scripts and tests")

        _seed_roles(conn)
        counts["adminCreated"] = _seed_admin(conn)
    return counts


def _seed_roles(conn) -> None:
    """System roles are defined in code and refreshed on every start, so their permissions can't drift."""
    for r in SYSTEM_ROLES:
        conn.execute(
            """INSERT INTO role (role_key, name, description, is_system) VALUES (%s, %s, %s, true)
               ON CONFLICT (role_key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, is_system = true""",
            (r["key"], r["name"], r["description"]),
        )
        conn.execute("DELETE FROM role_permission WHERE role_key = %s", (r["key"],))
        for p in r["permissions"]:
            conn.execute("INSERT INTO role_permission (role_key, permission) VALUES (%s, %s)", (r["key"], p))


def _seed_admin(conn) -> int:
    """First administrator, only when there are no users. Must change the password and enrol 2FA at first sign-in."""
    if conn.execute("SELECT 1 FROM app_user LIMIT 1").fetchone():
        return 0
    if not settings.admin_password:
        log.warning("No users exist and IPAM_ADMIN_PASSWORD isn't set, so nobody can sign in to the UI")
        return 0
    row = conn.execute(
        """INSERT INTO app_user (username, full_name, password_hash, must_change_password, created_by)
           VALUES (%s, 'IPAM Administrator', %s, true, 'seed') RETURNING user_id""",
        (settings.admin_username.lower(), hash_password(settings.admin_password)),
    ).fetchone()
    conn.execute("INSERT INTO user_role (user_id, role_key) VALUES (%s, 'admin')", (row["user_id"],))
    log.info("created first administrator '%s' (password from IPAM_ADMIN_PASSWORD; change forced at first sign-in)", settings.admin_username)
    return 1
