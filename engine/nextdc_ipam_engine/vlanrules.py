"""Bulk VLAN assignment rule (spec §5.4 "Bulk rule", FR-07c).

A section may carry a ``vlanRule`` that names every subnet it hasn't explicitly
bound, e.g. "VLAN ID = 2000 + third octet, name = v{id}-DCS-{oct}". A /16 DCS
section can hold 240+ subnets, so typing each binding isn't realistic.

The rule is expanded into explicit ``vlanBindings`` when a draft is saved, so
the stored content (and its hash) says exactly which VLAN sits where.
"""

from __future__ import annotations

import copy
from typing import Any

from .errors import EngineError
from .template import Layout

DEFAULTS = {
    "idBase": None,
    "positionStep": 100,
    "keyPattern": "{section}-N{oct:03d}{half}",
    "namePattern": "v{id}-{section}-{oct}{half}",
    "descriptionPattern": "{section} subnet {relativeCidr}",
}


def _half(prefix: int, pos: int) -> str:
    return "" if prefix <= 24 else chr(ord("A") + pos)


def expand_vlan_rules(content: dict[str, Any], layout: Layout) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return (content with generated bindings added, VLAN definitions the rules need)."""
    out = copy.deepcopy(content)
    vlans: list[dict[str, Any]] = []
    sections = {(b.key, s.key): s for b in layout.blocks for s in b.sections}
    for b in out["blocks"]:
        for s in b.get("sections", []):
            rule = s.get("vlanRule")
            if not rule:
                continue
            r = {**DEFAULTS, **rule}
            if not isinstance(r["idBase"], int):
                raise EngineError("IPAM-TEMPLATE-INVALID", f"{b['blockKey']}/{s['sectionKey']}: vlanRule.idBase is required")
            laid = sections[(b["blockKey"], s["sectionKey"])]
            bindings = s.setdefault("vlanBindings", [])
            for sub in laid.subnets:
                if sub.vlan_key:
                    continue
                addr = int(sub.relative.network_address)
                oct3 = (addr >> 8) & 0xFF
                pos = (addr & 0xFF) // sub.relative.num_addresses if sub.relative.prefixlen > 24 else 0
                vals = {
                    "section": s["sectionKey"],
                    "oct": oct3,
                    "pos": pos,
                    "half": _half(sub.relative.prefixlen, pos),
                    "relativeCidr": str(sub.relative),
                }
                vals["id"] = r["idBase"] + oct3 + pos * r["positionStep"]
                if not (1 < vals["id"] <= 4094) or 1002 <= vals["id"] <= 1005:
                    raise EngineError(
                        "IPAM-VLAN-ID-INVALID",
                        f"vlanRule gives VLAN ID {vals['id']} for {sub.relative}, outside 2-4094 or reserved",
                    )
                key = r["keyPattern"].format(**vals).upper()
                vlans.append(
                    {
                        "vlanKey": key,
                        "vlanId": vals["id"],
                        "vlanName": r["namePattern"].format(**vals),
                        "class": r.get("class", s["sectionKey"]),
                        "securityZone": r.get("securityZone"),
                        "description": r["descriptionPattern"].format(**vals),
                    }
                )
                bindings.append({"relativeCidr": str(sub.relative), "vlanKey": key})
    return out, vlans
