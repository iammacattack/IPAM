# NEXTDC IPAM: proof of concept (R0.0)

This is a proof of concept for NEXTDC IP Address Management, built on FastAPI and PostgreSQL in Docker (ADR Option A), with a web UI in PAMdora's Aurora theme. It covers the parts nothing off the shelf does for NEXTDC:

- the site template engine;
- two-step site allocation from a pool (reserve, then confirm);
- name-based host and VLAN lookups.

People sign in with local accounts, roles and 2FA (the PAMdora model); scripts use API keys. The three reference workflows in spec §17 run as automated end-to-end tests.

Its scope and exit criteria are in `architecture/IPAM-POC-Scope-v0.1.md` in the IPAM sub-project (`OneDrive - NEXTDC Limited\Documents\Claude\Projects\Tools\Sub-Projects\IPAM`). The specification is there too. This POC is a build choice for the proof of concept, not the platform decision: the ADR still needs a thin NetBox spike against tests T1, T3 and T4.

## Quick start

Docker Desktop has to be running. Then, from the repository root:

```powershell
.\scripts\Initialize-IpamEnv.ps1      # writes .env; re-run after upgrades - it only adds missing settings
docker compose up --build -d          # UI and API on http://127.0.0.1:8820
```

1. Open <http://127.0.0.1:8820/>.
2. Sign in as `admin` with the `IPAM_ADMIN_PASSWORD` value from `.env`.
3. You'll be asked to choose a new password. Then set up 2FA by scanning a QR code with an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password and so on).
4. Save the 10 backup codes somewhere safe.
5. Add people on **Users**.

The UI has these pages:

- **Dashboard**
- **Templates:** versions, layout, host placement, validation, preview and release
- **Template builder** (Workflow 1): sections, split all, split and merge rows, VLANs, bulk rule
- **Sites** (Workflow 2): reserve, confirm, extend, release, design, host assignment
- **Lookup tester** (Workflow 3): host IP, VLAN attributes, manifest tokens
- **Library:** VLANs, host pools (with a members editor), address pools (prefixes and exclusions) and VRFs, with full add / change / delete. A delete is refused while anything uses the item and the UI shows what; an in-use VLAN can be deprecated instead
- **Governance:** audit log, users, roles, API keys (shown to roles that have them)
- **My account:** password, 2FA, backup codes

The UI is plain ES modules in `web/` with no build step, served by the API. Use **☀ Light / ☾ Dark** at the bottom of the menu to switch themes.

Other entry points:

- **Swagger UI:** <http://127.0.0.1:8820/docs>. Click **Authorize** and paste an API key (the development key is `IPAM_BOOTSTRAP_API_KEY` in `.env`).
- **OpenAPI contract:** `/api/v1/openapi.json`.
- **Stop:** `docker compose down`. The data persists in the `ipam_pgdata` volume. `docker compose down -v` deletes it.

Everything binds to `127.0.0.1` only. The database isn't published to the host at all.

## Sign-in, roles and 2FA

This is the PAMdora model; Entra ID SSO is deferred.

- **Local users.** Passwords are bcrypt-hashed and must be at least 12 characters, using three of four character classes. Five wrong passwords lock the account for 15 minutes. New users and resets get a temporary password, which must be changed at next sign-in.
- **Roles.** Each role is a fixed set of permissions:

  | Role | Permissions |
  |---|---|
  | Viewer | `read` |
  | Designer | `read`, `templates.write`, `templates.release`, `vlans.write`, `hostroles.write` |
  | Operator | `read`, `sites.deploy`, `sites.confirm`, `sites.release`, `hosts.assign` |
  | Auditor | `read`, `audit.read` |
  | Administrator | everything, including `pools.write` (address pools and VRFs), `users.manage` and `apikeys.manage` |

  The **Roles** page shows the grid.
- **2FA.** TOTP (RFC 6238) with 10 single-use backup codes:
  - anyone enrolled enters a code at sign-in;
  - Administrators *must* enrol before they can do anything;
  - TOTP secrets are sealed at rest with AES-256-GCM (`IPAM_SECRET_KEY`);
  - a code can't be replayed.
- **Step-up.** These actions ask for a fresh code:
  - releasing a template;
  - confirming or releasing a site;
  - changing users;
  - issuing or revoking API keys;
  - replacing your own authenticator.

  One code covers 5 minutes. The API side: the call fails with `IPAM-STEP-UP-REQUIRED`, and the client repeats it with `X-IPAM-2FA: <code>`. The list of actions and the window are settings (`stepUpActions`, `stepUpWindowMinutes`).
- **Sessions.** Server-side, referenced by an `HttpOnly; SameSite=Strict` cookie that JavaScript can't read. The token is rotated when 2FA completes. A session ends after 30 minutes idle or 8 hours. Browser writes must carry `X-Requested-With: IPAM-UI` (CSRF guard). Set `IPAM_COOKIE_SECURE=true` behind TLS.
- **API keys** are for machines (spec §10.4):
  - they're issued on the **API keys** page, with a named owner, a purpose, scopes and an expiry of 365 days at most;
  - they skip 2FA, and can never manage users or keys;
  - scopes are `read`, `hosts:write`, `sites:deploy`, `templates:write` and `audit:read`;
  - the development key in `.env` has all of them, for tests and scripts.

## Tests

```powershell
docker compose --profile test run --rm --build tests
```

That runs the engine unit tests and the end-to-end suite inside the Compose network, against the running API. There are 73 tests:

- engine unit tests;
- Workflows 1, 2, 3 and 3a;
- ADR tests T1, T2, T3 and T6;
- sign-in, lockout, 2FA, step-up, CSRF, and user and key administration.

**The end-to-end suite clears all site allocations first** (sites, blocks, subnets, IP records, the site-code registry), so that Workflow 2's `X9` deploy is repeatable. It also removes its own `pt-*` test users and `WF1-*` templates. Real users, other templates, the VLAN library and the audit log are kept. Don't run it against sites you want to keep.

The engine tests also run locally without Docker:

```powershell
python -m venv .venv; .\.venv\Scripts\pip install pytest pyyaml
$env:PYTHONPATH = "$PWD\engine"; .\.venv\Scripts\python -m pytest tests/engine
```

## Try it from PowerShell

```powershell
$h = @{ 'X-API-Key' = '[API-KEY]'; 'X-Client-Name' = 'PowerShell/demo' }
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
| Sign-in and account | `POST /auth/login`, `POST /auth/mfa/verify`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/change-password`, `POST /auth/mfa/enrol`, `POST /auth/mfa/enrol/verify`, `POST /auth/mfa/backup-codes` |
| Administration | `GET/POST /users`, `PATCH /users/{u}`, `POST /users/{u}:reset-password`, `:reset-mfa`, `:unlock`, `GET /roles`, `GET/POST /api-keys`, `POST /api-keys/{prefix}:revoke` |
| Library (MACD) | VLANs: `GET/POST /vlans`, `GET/PATCH/DELETE /vlans/{key}`, `GET /vlans/{key}/usage`. Host pools: `GET/POST /host-roles`, `PATCH/DELETE /host-roles/{code}`, `PUT /host-roles/{code}/members`. Pools: `GET/POST /pools`, `PATCH/DELETE /pools/{key}`, `POST/DELETE /pools/{key}/prefixes`, `POST/DELETE /pools/{key}/exclusions`, `GET /pools/{key}/next-free`. VRFs: `GET/POST /vrfs`, `PATCH/DELETE /vrfs/{key}`, `GET /vrfs/{key}/usage` |
| Templates | `GET/POST /templates`, `GET /templates/{key}`, `POST /templates/{key}/versions`, `GET/PATCH /templates/{key}/versions/{v}`, `POST …/{v}:validate`, `POST …/{v}:release`, `GET …/{v}/placement`, `GET /templates/{key}/preview`, `POST /templates:layout` |
| Sites | `POST /sites` (reserve; `?dryRun=true`; `Idempotency-Key`), `POST /sites/{code}:confirm`, `:extend`, `:release`, `GET /sites`, `GET /sites/{code}`, `GET /sites/{code}/design`, `GET /sites/{code}/vlans/{vlan}` |
| Lookups | `GET /lookup/host-ip` (`resolve=assign`), `GET /lookup/vlan` (every §8.2.1 field plus `validateOctet`), `GET /lookup/network`, `POST /lookup:resolve-tokens` |
| Governance | `GET /audit`, `GET /site-codes`, `GET /healthz`, `GET /readyz` |

`POST /templates:layout` lays out unsaved template content for the builder. It's also where a bulk rule's proposed VLANs appear before they're saved.

These are deferred to later phases:
- Entra ID SSO (now after local users; see the POC scope);
- the hash-chained audit and SIEM forwarding;
- the `TESTING` state and two-person release;
- site retire and drift detection;
- the legacy import;
- the MCP server and PowerShell module;
- high availability.

The builder edits only the first block of a multi-block template, and there are no version compare or migration views yet.

## Repository layout

```
web/               UI: index.html, app.css (Aurora tokens), js/ ES modules, no build step
engine/            nextdc_ipam_engine - layout, split/merge, host addressing, lookups (stdlib only)
api/app/           FastAPI app: routers/, services/, auth + security (users, 2FA, keys), audit, bootstrap
api/migrations/    SQL schema (exclusion constraints, append-only audit, users and sessions)
seed/              VRFs, pools, VLAN library, host pools, templates, settings - loaded if absent
tests/engine/      engine unit tests (spec §5.6 worked examples, 265-subnet reconciliation)
tests/e2e/         workflows, ADR tests and sign-in/2FA tests against the live stack
scripts/           Initialize-IpamEnv.ps1
```

## Decisions and deviations worth knowing

- **Library guards.**
  - A VLAN's key never changes, and its ID is frozen while a live site carries it.
  - Host pools sharing a VLAN can't collide (spec §7), and a pool change that would leave a released template with placement conflicts is refused.
  - A pool prefix with allocations can't be removed, and an exclusion can't cover allocated space.
  - A non-private prefix needs explicit confirmation (spec §5.3).
  - Changes never move addresses already held at sites (spec §5.6).
- **Integrity is in the database.**
  - Site blocks can't overlap anywhere, because `EXCLUDE USING gist` enforces enterprise uniqueness.
  - Subnets can't overlap within a VRF.
  - A subnet must sit inside its block (trigger).
  - A released template version's content is frozen (trigger).
  - There's at most one `RELEASED` version per key (partial unique index).
  - The audit table is append-only (trigger).
  - API keys can't hold destructive scopes (check constraint).

  Test T1 proves a direct SQL insert is refused.
- **Bulk VLAN rule (FR-07c).** A section's `vlanRule` (e.g. VLAN ID = 2000 + third octet) is expanded into explicit bindings when a draft is saved, and it creates the VLAN library entries it needs. The stored content, and so its hash, always lists every binding.
- **Host position index outside the subnet's span** (e.g. `4.10` on a /22, or `1.10` on a /24) is a configuration error, `IPAM-HOST-POSITION-INVALID`, not a fallback case.
- **`spansThirdOctets` uses an ASCII hyphen** (`80-83`), not the spec's en dash, so the value is safe in shell scripts.
- **A host member on more than one VLAN** (e.g. `WDC01` on `CORP-SERVERS` and `DCS-SERVERS`) must be looked up with `vlan=`. Without it the API returns `IPAM-VLAN-REQUIRED`.
- **"Standard" site-code format** is assumed to be 1-3 letters then 1-2 digits (`X9`, `PH1`). Anything else is accepted and flagged `nonStandard`. Check this against `STD-INF-SITE-NAMING` §3.1.
- **Spec §10 changes.**
  - Entra ID SSO is deferred in favour of PAMdora-style local users.
  - The spec's roles (Viewer, Designer, Operator, Auditor, Administrator) are kept.
  - API keys with `sites:deploy` or `templates:write` can confirm sites and release templates without 2FA, as R17 allows.
- **Seed assumptions** (all configuration):
  - `DCS-SERVERS` is VLAN 2013 at `0.0.13.0/24`, matching the spec §8.2.1 example.
  - The home VLANs for MSS, RELAY and Genetec are guesses.
  - `NVR01` at position `1.10` is a fixture for the supernet example.
  - Legacy /16s aren't excluded from `SITE-POOL-AU` yet (that's the import phase), so the first deploy gets `10.1.0.0/16` rather than the spec's illustrative `10.9.0.0/16`.
