-- NEXTDC IPAM POC schema (spec §5, §7, §10.4, §11.1).
-- Integrity rests on the database as the backstop: overlap is an exclusion
-- constraint, not an application check (ADR test T1).

CREATE EXTENSION IF NOT EXISTS btree_gist;

-- --------------------------------------------------------------------------
-- Design data
-- --------------------------------------------------------------------------

CREATE TABLE vrf (
    vrf_key      text PRIMARY KEY,
    description  text
);

CREATE TABLE pool (
    pool_key                  text PRIMARY KEY,
    parent_key                text REFERENCES pool (pool_key),
    vrf_key                   text NOT NULL REFERENCES vrf (vrf_key),
    allocation_prefix_length  int CHECK (allocation_prefix_length BETWEEN 8 AND 30),
    strategy                  text NOT NULL DEFAULT 'first-fit' CHECK (strategy IN ('first-fit', 'sequential-from-last')),
    uniqueness                text NOT NULL DEFAULT 'enterprise' CHECK (uniqueness IN ('enterprise', 'vrf')),
    status                    text NOT NULL DEFAULT 'active',
    description               text
);

CREATE TABLE pool_prefix (
    pool_key  text NOT NULL REFERENCES pool (pool_key) ON DELETE CASCADE,
    cidr      cidr NOT NULL,
    position  int NOT NULL,
    PRIMARY KEY (pool_key, cidr)
);

CREATE TABLE pool_exclusion (
    pool_key  text NOT NULL REFERENCES pool (pool_key) ON DELETE CASCADE,
    cidr      cidr NOT NULL,
    PRIMARY KEY (pool_key, cidr)
);

CREATE TABLE vlan (
    vlan_key       text PRIMARY KEY CHECK (vlan_key ~ '^[A-Z0-9][A-Z0-9_-]*$'),
    vlan_id        int CHECK (vlan_id BETWEEN 2 AND 4094 AND vlan_id NOT BETWEEN 1002 AND 1005),
    vlan_name      text NOT NULL UNIQUE,
    class          text,
    security_zone  text CHECK (security_zone IN ('Internal', 'DataCentre', 'DMZ', 'OOB', 'Perimeter')),
    description    text,
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deprecated')),
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vlan_alias (
    alias     text NOT NULL,
    vlan_key  text NOT NULL REFERENCES vlan (vlan_key) ON DELETE CASCADE,
    PRIMARY KEY (alias, vlan_key)
);
CREATE INDEX vlan_alias_upper ON vlan_alias (upper(alias));

CREATE TABLE host_role (
    role_code         text PRIMARY KEY,
    name              text,
    vlan_keys         text[] NOT NULL DEFAULT '{}',
    hostname_pattern  text,
    offset_mode       text NOT NULL DEFAULT 'literalOctet' CHECK (offset_mode IN ('literalOctet', 'fromNetwork'))
);

CREATE TABLE host_role_member (
    role_code             text NOT NULL REFERENCES host_role (role_code) ON DELETE CASCADE,
    name                  text NOT NULL,
    ordinal               int NOT NULL,
    kind                  text NOT NULL CHECK (kind IN ('fixed', 'range', 'reserved')),
    host_position         text,
    secondary_host_octet  int CHECK (secondary_host_octet BETWEEN 0 AND 255),
    range_start           int,
    range_end             int,
    PRIMARY KEY (role_code, name)
);

CREATE TABLE setting (
    key    text PRIMARY KEY,
    value  jsonb NOT NULL
);

-- --------------------------------------------------------------------------
-- Templates (spec §5.5.1)
-- --------------------------------------------------------------------------

CREATE TABLE template (
    template_key  text PRIMARY KEY CHECK (template_key ~ '^[A-Z0-9][A-Z0-9-]*$'),
    description   text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    text
);

CREATE TABLE template_version (
    template_key   text NOT NULL REFERENCES template (template_key),
    version        int NOT NULL,
    state          text NOT NULL DEFAULT 'DRAFT'
                   CHECK (state IN ('DRAFT', 'TESTING', 'RELEASED', 'DEPRECATED', 'RETIRED')),
    content        jsonb NOT NULL,
    content_hash   text NOT NULL,
    summary        jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     text,
    released_at    timestamptz,
    released_by    text,
    release_notes  text,
    evidence       text,
    PRIMARY KEY (template_key, version)
);

-- At most one RELEASED version per template key.
CREATE UNIQUE INDEX template_one_released ON template_version (template_key) WHERE state = 'RELEASED';

-- A version that has left DRAFT is frozen: its content can never change.
CREATE FUNCTION template_version_frozen() RETURNS trigger AS $$
BEGIN
    IF OLD.state <> 'DRAFT' AND (NEW.content IS DISTINCT FROM OLD.content OR NEW.content_hash IS DISTINCT FROM OLD.content_hash) THEN
        RAISE EXCEPTION 'template %@v% is % and frozen', OLD.template_key, OLD.version, OLD.state
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER template_version_frozen
    BEFORE UPDATE ON template_version
    FOR EACH ROW EXECUTE FUNCTION template_version_frozen();

-- --------------------------------------------------------------------------
-- Sites and allocations
-- --------------------------------------------------------------------------

CREATE TABLE site_code (
    code            text PRIMARY KEY,
    country_code    text,
    status          text NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified', 'verified')),
    non_standard    boolean NOT NULL DEFAULT false,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    first_seen_by   text
);

CREATE TABLE site (
    site_id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    site_code              text NOT NULL REFERENCES site_code (code),
    country_code           text,
    status                 text NOT NULL CHECK (status IN
                           ('reserved', 'allocated', 'active', 'decommissioning', 'retired', 'released', 'expired')),
    template_key           text,
    template_version       int,
    template_content_hash  text,
    reservation_id         uuid,
    expires_at             timestamptz,
    reserved_by            text,
    client_name            text,
    idempotency_key        text UNIQUE,
    external_ref           text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    confirmed_at           timestamptz,
    confirmed_by           text,
    ended_at               timestamptz,
    FOREIGN KEY (template_key, template_version) REFERENCES template_version (template_key, version)
);

-- A site code can be held by only one live site.
CREATE UNIQUE INDEX site_code_live ON site (site_code)
    WHERE status IN ('reserved', 'allocated', 'active', 'decommissioning');

CREATE TABLE block (
    block_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id    uuid NOT NULL REFERENCES site (site_id) ON DELETE CASCADE,
    block_key  text NOT NULL,
    vrf_key    text NOT NULL REFERENCES vrf (vrf_key),
    pool_key   text REFERENCES pool (pool_key),
    cidr       cidr NOT NULL,
    -- Pools default to enterprise uniqueness: no two site blocks overlap in any VRF.
    CONSTRAINT block_no_overlap EXCLUDE USING gist (cidr inet_ops WITH &&)
);

CREATE TABLE subnet (
    subnet_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id        uuid NOT NULL REFERENCES site (site_id) ON DELETE CASCADE,
    block_id       uuid NOT NULL REFERENCES block (block_id) ON DELETE CASCADE,
    section        text NOT NULL,
    vrf_key        text NOT NULL REFERENCES vrf (vrf_key),
    cidr           cidr NOT NULL,
    relative_cidr  cidr NOT NULL,
    vlan_key       text REFERENCES vlan (vlan_key),
    vlan_id        int,
    gateway        inet,
    status         text NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved', 'active', 'deprecated')),
    origin         text NOT NULL DEFAULT 'template' CHECK (origin IN ('template', 'manual', 'import')),
    CONSTRAINT subnet_no_overlap EXCLUDE USING gist (vrf_key WITH =, cidr inet_ops WITH &&),
    CONSTRAINT subnet_gateway_inside CHECK (gateway IS NULL OR gateway << cidr),
    UNIQUE (site_id, vlan_key),
    UNIQUE (site_id, vlan_id)
);
CREATE INDEX subnet_site ON subnet (site_id);

-- A subnet lies entirely inside its block (spec §7).
CREATE FUNCTION subnet_inside_block() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM block b WHERE b.block_id = NEW.block_id AND NEW.cidr <<= b.cidr) THEN
        RAISE EXCEPTION 'subnet % is outside its block', NEW.cidr USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER subnet_inside_block
    BEFORE INSERT OR UPDATE OF cidr, block_id ON subnet
    FOR EACH ROW EXECUTE FUNCTION subnet_inside_block();

CREATE TABLE ip_record (
    ip_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id        uuid NOT NULL REFERENCES site (site_id) ON DELETE CASCADE,
    subnet_id      uuid NOT NULL REFERENCES subnet (subnet_id) ON DELETE CASCADE,
    vrf_key        text NOT NULL,
    ip             inet NOT NULL,
    status         text NOT NULL CHECK (status IN ('gateway', 'reserved-pattern', 'reserved', 'assigned')),
    role_code      text,
    member_name    text,
    host_position  text,
    octet_used     text CHECK (octet_used IN ('primary', 'secondary', 'calculated')),
    hostname       text,
    assigned_at    timestamptz,
    assigned_by    text,
    UNIQUE (vrf_key, ip)
);
CREATE INDEX ip_record_subnet ON ip_record (subnet_id);
CREATE UNIQUE INDEX ip_record_hostname ON ip_record (lower(hostname)) WHERE hostname IS NOT NULL;

-- --------------------------------------------------------------------------
-- Security and audit
-- --------------------------------------------------------------------------

CREATE TABLE api_key (
    key_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    prefix        text NOT NULL UNIQUE,
    secret_hash   text NOT NULL,
    owner         text NOT NULL,
    purpose       text,
    client_name   text,
    scopes        text[] NOT NULL,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    last_used_at  timestamptz,
    last_used_ip  inet,
    -- Destructive scopes can't be granted to keys (spec §10.4).
    CONSTRAINT api_key_no_destructive CHECK (NOT (scopes && ARRAY['sites:delete', 'admin:*']))
);

CREATE TABLE audit_event (
    event_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id     uuid,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    actor_type     text NOT NULL,
    actor_id       text,
    actor_display  text,
    auth_method    text,
    mfa            text,
    source_ip      inet,
    user_agent     text,
    client_name    text,
    http_method    text,
    route          text,
    query          text,
    action         text NOT NULL,
    object_type    text,
    object_key     text,
    site_code      text,
    outcome        text NOT NULL,
    status_code    int,
    error_code     text,
    duration_ms    int,
    changes        jsonb
);
CREATE INDEX audit_occurred ON audit_event (occurred_at DESC);
CREATE INDEX audit_action ON audit_event (action);
CREATE INDEX audit_site ON audit_event (site_code);

-- Append-only (spec §11.2). The hash chain is Phase 4; this stops casual edits now.
CREATE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_event is append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_append_only
    BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
