"""Template parsing and layout (spec §5.5, §6.1 steps 2-5).

Everything here works in *relative* address space: a /16 block is laid out as
``0.0.0.0/16`` and every subnet is expressed relative to it (``0.0.13.0/24``).
That's exactly how templates store overrides and bindings, and it means the
same layout replays identically at every site - materialising is just adding
the site's block base address (see ``materialise``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from .errors import EngineError, EngineValidationError

MIN_SUBNET_PREFIX = 16
MAX_SUBNET_PREFIX = 30


# --------------------------------------------------------------------------- #
# Parsed template shape
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Extent:
    start: int | None  # unit index, or None for "auto"
    kind: str  # "units" | "remaining" | "upTo"
    units: int | None


@dataclass(frozen=True)
class Override:
    raw: str
    kind: str  # "split" | "merge"
    target_prefix: int


@dataclass(frozen=True)
class Binding:
    raw: str
    vlan_key: str
    gateway_offset: int


@dataclass
class SectionSpec:
    key: str
    org_domain: str | None
    vrf: str
    extent: Extent
    overrides: list[Override]
    bindings: list[Binding]
    vlan_rule: dict[str, Any] | None


@dataclass
class BlockSpec:
    key: str
    prefix_length: int
    vrf: str
    default_pool: str | None
    unit_prefix: int
    sections: list[SectionSpec]


@dataclass
class TemplateSpec:
    blocks: list[BlockSpec]


# --------------------------------------------------------------------------- #
# Layout result
# --------------------------------------------------------------------------- #


@dataclass
class LayoutSubnet:
    block_key: str
    section: str
    vrf: str
    relative: IPv4Network
    vlan_key: str | None = None
    gateway_offset: int = 1

    @property
    def relative_cidr(self) -> str:
        return str(self.relative)


@dataclass
class SectionLayout:
    key: str
    vrf: str
    org_domain: str | None
    start: IPv4Address  # relative
    units: int
    subnets: list[LayoutSubnet] = field(default_factory=list)


@dataclass
class BlockLayout:
    key: str
    prefix_length: int
    vrf: str
    default_pool: str | None
    unit_prefix: int
    sections: list[SectionLayout] = field(default_factory=list)

    @property
    def subnets(self) -> list[LayoutSubnet]:
        return [s for sec in self.sections for s in sec.subnets]


@dataclass
class Layout:
    blocks: list[BlockLayout]

    @property
    def subnets(self) -> list[LayoutSubnet]:
        return [s for b in self.blocks for s in b.subnets]

    def summary(self) -> dict[str, Any]:
        """Per-section subnet counts; the Workflow 1 reconciliation check reads this."""
        out = []
        for b in self.blocks:
            for sec in b.sections:
                sizes: dict[str, int] = {}
                for s in sec.subnets:
                    sizes[f"/{s.relative.prefixlen}"] = sizes.get(f"/{s.relative.prefixlen}", 0) + 1
                out.append(
                    {
                        "blockKey": b.key,
                        "sectionKey": sec.key,
                        "vrf": sec.vrf,
                        "start": str(sec.start),
                        "units": sec.units,
                        "subnets": len(sec.subnets),
                        "bySize": sizes,
                        "bound": sum(1 for s in sec.subnets if s.vlan_key),
                    }
                )
        return {"subnetCount": len(self.subnets), "sections": out}


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _invalid(msg: str, **detail: Any) -> EngineError:
    return EngineError("IPAM-TEMPLATE-INVALID", msg, **detail)


def _unit_index(offset: str, unit_size: int, where: str) -> int:
    try:
        addr = int(IPv4Address(offset))
    except ValueError as exc:
        raise _invalid(f"{where}: start '{offset}' isn't an IPv4 offset like 0.0.64.0") from exc
    if addr % unit_size:
        raise EngineError(
            "IPAM-EXTENT-MISALIGNED",
            f"{where}: start {offset} isn't on a unit boundary",
            start=offset,
        )
    return addr // unit_size


def _parse_extent(raw: Any, unit_size: int, where: str) -> Extent:
    if not isinstance(raw, dict):
        raise _invalid(f"{where}: extent must be an object")
    start_raw = raw.get("start", "auto")
    start = None if start_raw in (None, "auto") else _unit_index(str(start_raw), unit_size, where)
    units = raw.get("units")
    if units == "remaining":
        return Extent(start, "remaining", None)
    if isinstance(units, dict) and "upTo" in units:
        n = units["upTo"]
        if not isinstance(n, int) or n < 1:
            raise _invalid(f"{where}: upTo must be a positive integer")
        return Extent(start, "upTo", n)
    if isinstance(units, int) and not isinstance(units, bool) and units >= 1:
        return Extent(start, "units", units)
    raise _invalid(f"{where}: extent.units must be a positive integer, 'remaining' or {{'upTo': n}}")


def _parse_override(raw: Any, where: str) -> Override:
    if not isinstance(raw, dict) or "relativeCidr" not in raw:
        raise _invalid(f"{where}: each subnetOverride needs a relativeCidr")
    cidr = str(raw["relativeCidr"])
    if "splitTo" in raw:
        return Override(cidr, "split", int(raw["splitTo"]))
    if "mergeFrom" in raw or raw.get("merge") is True:
        # The merge target is the relativeCidr's own prefix length.
        try:
            target = int(cidr.split("/")[1])
        except (IndexError, ValueError) as exc:
            raise _invalid(f"{where}: merge relativeCidr needs a prefix length") from exc
        return Override(cidr, "merge", target)
    raise _invalid(f"{where}: subnetOverride needs splitTo or mergeFrom")


def _parse_binding(raw: Any, where: str) -> Binding:
    if not isinstance(raw, dict) or "relativeCidr" not in raw or "vlanKey" not in raw:
        raise _invalid(f"{where}: each vlanBinding needs relativeCidr and vlanKey")
    gw = raw.get("gateway") or {}
    offset = gw.get("offset", 1) if isinstance(gw, dict) else 1
    return Binding(str(raw["relativeCidr"]), str(raw["vlanKey"]), int(offset))


def parse_template(content: dict[str, Any]) -> TemplateSpec:
    if not isinstance(content, dict):
        raise _invalid("template content must be an object")
    blocks_raw = content.get("blocks")
    if not isinstance(blocks_raw, list) or not blocks_raw:
        raise _invalid("template needs at least one block")
    blocks: list[BlockSpec] = []
    seen_blocks: set[str] = set()
    for b in blocks_raw:
        key = str(b.get("blockKey", ""))
        if not key or key in seen_blocks:
            raise _invalid(f"block key '{key}' is missing or duplicated")
        seen_blocks.add(key)
        plen = int(b.get("prefixLength", 0))
        unit = int(b.get("unitPrefix", 24))
        if not (8 <= plen <= 24):
            raise _invalid(f"block {key}: prefixLength must be /8 to /24", blockKey=key)
        if not (plen <= unit <= MAX_SUBNET_PREFIX):
            raise _invalid(f"block {key}: unitPrefix must be between the block prefix and /30", blockKey=key)
        unit_size = 2 ** (32 - unit)
        sections: list[SectionSpec] = []
        seen_sections: set[str] = set()
        for s in b.get("sections", []):
            skey = str(s.get("sectionKey", ""))
            where = f"{key}/{skey}"
            if not skey or skey in seen_sections:
                raise _invalid(f"section key '{skey}' is missing or duplicated in block {key}")
            seen_sections.add(skey)
            sections.append(
                SectionSpec(
                    key=skey,
                    org_domain=s.get("orgDomain"),
                    vrf=str(s.get("vrf") or b.get("vrf")),
                    extent=_parse_extent(s.get("extent", {}), unit_size, where),
                    overrides=[_parse_override(o, where) for o in s.get("subnetOverrides", []) or []],
                    bindings=[_parse_binding(x, where) for x in s.get("vlanBindings", []) or []],
                    vlan_rule=s.get("vlanRule"),
                )
            )
        if not sections:
            raise _invalid(f"block {key} needs at least one section")
        blocks.append(
            BlockSpec(
                key=key,
                prefix_length=plen,
                vrf=str(b.get("vrf", "")),
                default_pool=b.get("defaultPool"),
                unit_prefix=unit,
                sections=sections,
            )
        )
    return TemplateSpec(blocks)


# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #


def _resolve_extents(block: BlockSpec, errors: list[EngineError]) -> list[tuple[SectionSpec, int, int]]:
    """Return (section, start_unit, unit_count) in declaration order (spec §6.1 step 2)."""
    total = 2 ** (block.unit_prefix - block.prefix_length)
    resolved: list[tuple[SectionSpec, int, int]] = []
    cursor = 0
    for i, sec in enumerate(block.sections):
        start = cursor if sec.extent.start is None else sec.extent.start
        # "remaining" runs to the next explicitly pinned section, or the block end.
        limit = total
        for later in block.sections[i + 1 :]:
            if later.extent.start is not None and later.extent.start >= start:
                limit = later.extent.start
                break
        available = limit - start
        if sec.extent.kind == "units":
            size = sec.extent.units or 0
        elif sec.extent.kind == "remaining":
            size = available
        else:
            size = min(sec.extent.units or 0, available)
        where = f"{block.key}/{sec.key}"
        if size < 1:
            errors.append(EngineError("IPAM-EXTENT-EMPTY", f"{where}: no space left for this section"))
            continue
        if start < 0 or start + size > total:
            errors.append(
                EngineError(
                    "IPAM-EXTENT-OVERRUN",
                    f"{where}: {size} units from unit {start} overruns the block ({total} units)",
                )
            )
            continue
        for other, o_start, o_size in resolved:
            if start < o_start + o_size and o_start < start + size:
                errors.append(
                    EngineError(
                        "IPAM-EXTENT-OVERLAP",
                        f"{where}: overlaps section {other.key}",
                        section=sec.key,
                        overlapsWith=other.key,
                    )
                )
                break
        else:
            resolved.append((sec, start, size))
        cursor = start + size
    return resolved


def _apply_override(
    subnets: list[IPv4Network], ov: Override, sec_lo: int, sec_hi: int, where: str
) -> list[IPv4Network]:
    try:
        net = IPv4Network(ov.raw, strict=True)
    except ValueError:
        try:
            loose = IPv4Network(ov.raw, strict=False)
        except ValueError as exc:
            raise _invalid(f"{where}: '{ov.raw}' isn't a CIDR") from exc
        if ov.kind == "merge":
            raise EngineError(
                "IPAM-MERGE-MISALIGNED",
                f"{where}: {ov.raw} isn't on a /{loose.prefixlen} boundary",
                requested=ov.raw,
                suggested=str(loose),
            )
        raise _invalid(f"{where}: {ov.raw} has host bits set; did you mean {loose}?")

    lo, hi = int(net.network_address), int(net.broadcast_address)
    if lo < sec_lo or hi > sec_hi:
        raise EngineError(
            "IPAM-OVERRIDE-OUTSIDE-SECTION",
            f"{where}: {net} crosses the section boundary",
            override=str(net),
        )

    if ov.kind == "split":
        if not (net.prefixlen < ov.target_prefix <= MAX_SUBNET_PREFIX):
            raise _invalid(f"{where}: splitTo /{ov.target_prefix} must be longer than {net} and at most /30")
        if net not in subnets:
            raise EngineError(
                "IPAM-OVERRIDE-NO-MATCH",
                f"{where}: {net} isn't a subnet in the layout at this point, so it can't be split",
                override=str(net),
            )
        i = subnets.index(net)
        return subnets[:i] + list(net.subnets(new_prefix=ov.target_prefix)) + subnets[i + 1 :]

    # merge
    if net.prefixlen < MIN_SUBNET_PREFIX:
        raise _invalid(f"{where}: can't merge beyond /{MIN_SUBNET_PREFIX}")
    inside = [s for s in subnets if s.overlaps(net)]
    for s in inside:
        if not s.subnet_of(net):
            raise EngineError(
                "IPAM-OVERRIDE-OVERLAP",
                f"{where}: {net} would cut across existing subnet {s}",
                override=str(net),
                conflictsWith=str(s),
            )
    if sum(s.num_addresses for s in inside) != net.num_addresses:
        raise EngineError(
            "IPAM-OVERRIDE-NO-MATCH",
            f"{where}: {net} doesn't cover a complete set of existing subnets",
            override=str(net),
        )
    if inside == [net]:
        return subnets
    first = subnets.index(inside[0])
    rest = [s for s in subnets if s not in inside]
    return rest[:first] + [net] + rest[first:]


def compute_layout(spec: TemplateSpec) -> Layout:
    """Lay the template out in relative space. Raises EngineValidationError listing every problem found."""
    errors: list[EngineError] = []
    blocks: list[BlockLayout] = []
    for block in spec.blocks:
        unit_size = 2 ** (32 - block.unit_prefix)
        bl = BlockLayout(block.key, block.prefix_length, block.vrf, block.default_pool, block.unit_prefix)
        for sec, start_unit, n_units in _resolve_extents(block, errors):
            where = f"{block.key}/{sec.key}"
            sec_lo = start_unit * unit_size
            sec_hi = sec_lo + n_units * unit_size - 1
            nets = [IPv4Network((sec_lo + i * unit_size, block.unit_prefix)) for i in range(n_units)]

            def _ov_key(o: Override) -> tuple[int, int]:
                try:
                    n = IPv4Network(o.raw, strict=False)
                    return (int(n.network_address), n.prefixlen)
                except ValueError:
                    return (0, 0)

            for ov in sorted(sec.overrides, key=_ov_key):
                try:
                    nets = _apply_override(nets, ov, sec_lo, sec_hi, where)
                except EngineError as err:
                    errors.append(err)

            sl = SectionLayout(sec.key, sec.vrf, sec.org_domain, IPv4Address(sec_lo), n_units)
            sl.subnets = [LayoutSubnet(block.key, sec.key, sec.vrf, n) for n in nets]
            by_net = {s.relative: s for s in sl.subnets}

            for b in sec.bindings:
                try:
                    bnet = IPv4Network(b.raw, strict=True)
                except ValueError:
                    errors.append(_invalid(f"{where}: binding '{b.raw}' isn't a valid network"))
                    continue
                target = by_net.get(bnet)
                if target is None:
                    overlapped = [str(s.relative) for s in sl.subnets if s.relative.overlaps(bnet)]
                    if overlapped:
                        errors.append(
                            EngineError(
                                "IPAM-BINDING-ORPHANED",
                                f"{where}: {bnet} ({b.vlan_key}) no longer exists after split/merge",
                                relativeCidr=str(bnet),
                                vlanKey=b.vlan_key,
                                nowCoveredBy=overlapped,
                            )
                        )
                    else:
                        errors.append(
                            EngineError(
                                "IPAM-BINDING-NO-MATCH",
                                f"{where}: {bnet} ({b.vlan_key}) isn't inside this section",
                                relativeCidr=str(bnet),
                                vlanKey=b.vlan_key,
                            )
                        )
                    continue
                if target.vlan_key:
                    errors.append(
                        EngineError(
                            "IPAM-BINDING-DUPLICATE",
                            f"{where}: {bnet} is bound twice ({target.vlan_key}, {b.vlan_key})",
                            relativeCidr=str(bnet),
                        )
                    )
                    continue
                if not (1 <= b.gateway_offset <= bnet.num_addresses - 2):
                    errors.append(
                        EngineError(
                            "IPAM-GATEWAY-OUT-OF-RANGE",
                            f"{where}: gateway offset {b.gateway_offset} isn't usable in {bnet}",
                            relativeCidr=str(bnet),
                        )
                    )
                    continue
                target.vlan_key = b.vlan_key
                target.gateway_offset = b.gateway_offset
            bl.sections.append(sl)
        blocks.append(bl)

    # A VLAN key may appear once per template: lookups are keyed on site + VLAN.
    seen: dict[str, str] = {}
    for s in (s for b in blocks for s in b.subnets):
        if s.vlan_key:
            if s.vlan_key in seen:
                errors.append(
                    EngineError(
                        "IPAM-VLAN-DUPLICATE",
                        f"VLAN {s.vlan_key} is bound to both {seen[s.vlan_key]} and {s.relative}",
                        vlanKey=s.vlan_key,
                    )
                )
            else:
                seen[s.vlan_key] = str(s.relative)

    if errors:
        raise EngineValidationError(errors)
    return Layout(blocks)


def layout_from_content(content: dict[str, Any]) -> Layout:
    return compute_layout(parse_template(content))


# --------------------------------------------------------------------------- #
# Materialisation
# --------------------------------------------------------------------------- #


def relocate(relative: IPv4Network, base: IPv4Network) -> IPv4Network:
    return IPv4Network((int(base.network_address) + int(relative.network_address), relative.prefixlen))


def check_base(base_ip: str, prefix_length: int) -> IPv4Network:
    """Validate a client-supplied base (spec §6.1 step 1): reject misaligned, never silently correct."""
    raw = base_ip if "/" in base_ip else f"{base_ip}/{prefix_length}"
    try:
        net = IPv4Network(raw, strict=True)
    except ValueError:
        try:
            suggestion = IPv4Network(raw, strict=False).supernet(new_prefix=prefix_length)
        except ValueError as exc:
            raise EngineError("IPAM-BASEIP-INVALID", f"'{base_ip}' isn't an IPv4 address") from exc
        raise EngineError(
            "IPAM-BASEIP-MISALIGNED",
            f"{base_ip} isn't aligned to a /{prefix_length}",
            requested=base_ip,
            suggested=str(suggestion),
        )
    if net.prefixlen != prefix_length:
        raise EngineError(
            "IPAM-BASEIP-MISALIGNED",
            f"{base_ip} doesn't match the block size /{prefix_length}",
            requested=base_ip,
            suggested=str(net.supernet(new_prefix=prefix_length)) if net.prefixlen > prefix_length else None,
        )
    return net
