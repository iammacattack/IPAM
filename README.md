# NEXTDC IPAM: proof of concept (R0.0)

This is an API-only proof of concept for NEXTDC IP Address Management, built on FastAPI and PostgreSQL in Docker (ADR Option A). It covers the parts nothing off the shelf does for NEXTDC:

- the site template engine;
- two-step site allocation from a pool (reserve, then confirm);
- name-based host and VLAN lookups.

The three reference workflows in spec §17 run as automated end-to-end tests.

Its scope and exit criteria are in `architecture/IPAM-POC-Scope-v0.1.md` in the IPAM sub-project (`OneDrive - NEXTDC Limited\Documents\Claude\Projects\Tools\Sub-Projects\IPAM`). The specification is there too. This POC is a build choice for the proof of concept, not the platform decision: the ADR still needs a thin NetBox spike against tests T1, T3 and T4.

## Quick start

Docker Desktop has to be running. Then, from the repository root:

```powershell
.\scripts\Initialize-IpamEnv.ps1      # once: writes .env with a DB password and a development API key
docker compose up --build -d          # API on http://127.0.0.1:8820
```

- **Swagger UI:** <http://127.0.0.1:8820/docs>. Click **Authorize** and paste the `IPAM_BOOTSTRAP_API_KEY` value from `.env`.
- **OpenAPI contract:** `/api/v1/openapi.json`.
- **Stop:** `docker compose down`. The data persists in the `ipam_pgdata` volume. `docker compose down -v` deletes it.

Everything binds to `127.0.0.1` only. The database isn't published to the host at all.

## Tests

```powershell
docker compose --profile test run --rm --build tests
```

That runs the engine unit tests and the end-to-end suite inside the Compose network, against the running API.

**The end-to-end suite clears all site allocations first** (sites, blocks, subnets, IP records, the site-code registry), so that Workflow 2's `X9` deploy is repeatable. Templates, the VLAN library and the audit log are kept. Don't point it at data you want to keep.

The engine tests also run locally without Docker:

```powershell
python -m venv .venv; .\.venv\Scripts\pip install pytest pyyaml
$env:PYTHONPATH = "$PWD\engine"; .\.venv\Scripts\python -m pytest tests/engine
```

## Try it

```powershell
$h = @{ 'X-API-Key' = '[API-KEY-FROM-.env]'; 'X-Client-Name' = 'PowerShell/demo' }
$base = 'http://127.0.0.1:8820/api/v1'

# Workflow 2: reserve a site from the released template, no base IP (the pool picks the next free /16)
$site = Invoke-RestMethod "$base/sites" -Method Post -Headers $h -ContentType 'application/json' `
    -Body '{"siteCode":"X9","countryCode":"AU","templateKey":"EXAMPLE-NET-10"}'
Invoke-RestMethod "$base/sites/X9:confirm" -Method Post -Headers $h -ContentType 'application/json' `
    -Body (@{ reservationId = $site.reservation.reservationId } | ConvertTo-Json)

# Workflow 3: resolve manifest tokens by name
$h.Accept = 'text/plain'
Invoke-RestMethod "$base/lookup/host-ip?site=X9&vlan=VLAN_OT_SERVER&host=WDC01" -Headers $h            # 10.x.13.61
Invoke-RestMethod "$base/lookup/vlan?site=X9&vlan=VLAN_OT_SERVER&field=gateway" -Headers $h            # 10.x.13.1
Invoke-RestMethod "$base/lookup/vlan?site=X9&vlan=VLAN_OT_SERVER&field=dnsServers" -Headers $h         # 10.x.13.61,10.x.13.62
```

## What's in the POC

| Area | Endpoints |
|---|---|
| Design data | `GET /vrfs`, `GET /pools`, `GET /pools/{key}/next-free`, `GET/POST /vlans`, `GET /vlans/{keyOrAlias}`, `GET /host-roles` |
| Templates | `GET/POST /templates`, `GET /templates/{key}`, `POST /templates/{key}/versions`, `GET/PATCH /templates/{key}/versions/{v}`, `POST …/{v}:validate`, `POST …/{v}:release`, `GET …/{v}/placement`, `GET /templates/{key}/preview` |
| Sites | `POST /sites` (reserve; `?dryRun=true`; `Idempotency-Key`), `POST /sites/{code}:confirm`, `:extend`, `:release`, `GET /sites`, `GET /sites/{code}`, `GET /sites/{code}/design`, `GET /sites/{code}/vlans/{vlan}` |
| Lookups | `GET /lookup/host-ip` (`resolve=assign`), `GET /lookup/vlan` (every §8.2.1 field plus `validateOctet`), `GET /lookup/network`, `POST /lookup:resolve-tokens` |
| Governance | `GET /audit`, `GET /site-codes`, `GET /healthz`, `GET /readyz` |

These are deferred to later phases, per the POC scope: Entra ID and MFA, key scopes and expiry management, the hash-chained audit and SIEM forwarding, the `TESTING` state and two-person release, site retire and drift detection, the web UI, the legacy import, the MCP server and PowerShell module, and high availability.

## Repository layout

```
engine/            nextdc_ipam_engine - layout, split/merge, host addressing, lookups (stdlib only)
api/app/           FastAPI app: routers/, services/, auth, audit middleware, bootstrap
api/migrations/    SQL schema (exclusion constraints, append-only audit)
seed/              VRFs, pools, VLAN library, host pools, templates - configuration, loaded if absent
tests/engine/      engine unit tests (spec §5.6 worked examples, 265-subnet reconciliation)
tests/e2e/         Workflows 1, 2, 3/3a and ADR tests T1-T3, T6 against the live stack
scripts/           Initialize-IpamEnv.ps1
```

## Decisions and deviations worth knowing

- **Integrity is in the database.** Site blocks can't overlap anywhere, because `EXCLUDE USING gist` enforces enterprise uniqueness. Subnets can't overlap within a VRF. A subnet must sit inside its block (trigger). A released template version's content is frozen (trigger). There's at most one `RELEASED` version per key (partial unique index). The audit table is append-only (trigger). Test T1 proves a direct SQL insert is refused.
- **Bulk VLAN rule (FR-07c).** A section's `vlanRule` (e.g. VLAN ID = 2000 + third octet) is expanded into explicit bindings when a draft is saved, and it creates the VLAN library entries it needs. The stored content, and so its hash, always lists every binding.
- **Host position index outside the subnet's span** (e.g. `4.10` on a /22, or `1.10` on a /24) is a configuration error, `IPAM-HOST-POSITION-INVALID`, not a fallback case.
- **`spansThirdOctets` uses an ASCII hyphen** (`80-83`), not the spec's en dash, so the value is safe in shell scripts.
- **A host member on more than one VLAN** (e.g. `WDC01` on `CORP-SERVERS` and `DCS-SERVERS`) must be looked up with `vlan=`. Without it the API returns `IPAM-VLAN-REQUIRED`.
- **"Standard" site-code format** is assumed to be 1-3 letters then 1-2 digits (`X9`, `PH1`). Anything else is accepted and flagged `nonStandard`. Check this against `STD-INF-SITE-NAMING` §3.1.
- **Seed assumptions** (all configuration):
  - `DCS-SERVERS` is VLAN 2013 at `0.0.13.0/24`, matching the spec §8.2.1 example.
  - The home VLANs for MSS, RELAY and Genetec are guesses.
  - `NVR01` at position `1.10` is a fixture for the supernet example.
  - Legacy /16s aren't excluded from `SITE-POOL-AU` yet (that's the import phase), so the first deploy gets `10.1.0.0/16` rather than the spec's illustrative `10.9.0.0/16`.
