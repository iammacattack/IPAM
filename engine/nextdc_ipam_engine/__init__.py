"""nextdc_ipam_engine - platform-neutral template and host-addressing engine.

No web or database dependencies, so it works unchanged under FastAPI (ADR
Option A) or as a NetBox plugin (Option B).
"""

from .canonical import canonical_json, content_hash
from .errors import EngineError, EngineValidationError
from .hosts import HostPosition, Resolution, resolve_host, unusable_reason
from .lookup import ALL_FIELDS, NETWORK_FIELDS, network_portion, validate_octet, vlan_attributes
from .placement import HostPool, Placement, PoolMember, place_members, placement_matrix
from .template import Layout, LayoutSubnet, check_base, compute_layout, layout_from_content, parse_template, relocate
from .vlanrules import expand_vlan_rules

__version__ = "0.1.0"

__all__ = [
    "ALL_FIELDS",
    "NETWORK_FIELDS",
    "EngineError",
    "EngineValidationError",
    "HostPool",
    "HostPosition",
    "Layout",
    "LayoutSubnet",
    "Placement",
    "PoolMember",
    "Resolution",
    "canonical_json",
    "check_base",
    "compute_layout",
    "content_hash",
    "expand_vlan_rules",
    "layout_from_content",
    "network_portion",
    "parse_template",
    "place_members",
    "placement_matrix",
    "relocate",
    "resolve_host",
    "unusable_reason",
    "validate_octet",
    "vlan_attributes",
]
