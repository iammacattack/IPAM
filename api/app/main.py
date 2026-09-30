"""NEXTDC IPAM - proof of concept API (release R0.0).

FastAPI + PostgreSQL, API-key auth, every request audited. See
architecture/IPAM-POC-Scope-v0.1.md in the IPAM sub-project for what's in and out.
"""

from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from psycopg import errors as pg_errors

from nextdc_ipam_engine import EngineError, __version__ as engine_version

from . import bootstrap
from .audit import AuditMiddleware, system_event
from .config import API_PREFIX, settings
from .db import close_pool, open_pool, tx, wait_for_database
from .errors import IpamError, engine_error_handler, ipam_error_handler, problem
from .routers import admin, auth_routes, design, governance, lookups, sites
from .services import sites as ssvc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ipam")

API_VERSION = "0.0.1-poc"


def _sweeper(stop: threading.Event) -> None:
    """Expire lapsed site reservations even when nobody is calling the API."""
    while not stop.wait(settings.expiry_sweep_seconds):
        try:
            with tx() as conn:
                expired = ssvc.expire_due(conn)
            for code in expired:
                system_event("site.reservation_expired", objectType="site", objectKey=code, siteCode=code)
        except Exception:  # noqa: BLE001
            log.exception("reservation sweep failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    wait_for_database()
    open_pool()
    applied = bootstrap.migrate()
    if applied:
        log.info("applied migrations: %s", ", ".join(applied))
    log.info("seed: %s", bootstrap.seed())
    stop = threading.Event()
    t = threading.Thread(target=_sweeper, args=(stop,), name="reservation-sweeper", daemon=True)
    t.start()
    yield
    stop.set()
    close_pool()


app = FastAPI(
    title="NEXTDC IPAM (POC)",
    version=API_VERSION,
    description=(
        "Proof of concept for NEXTDC IP Address Management. Authenticate with `X-API-Key`. "
        "Send `X-Client-Name` so the audit log knows which tool called. "
        f"Engine {engine_version}."
    ),
    openapi_url=f"{API_PREFIX}/openapi.json",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(AuditMiddleware)
app.add_exception_handler(IpamError, ipam_error_handler)
app.add_exception_handler(EngineError, engine_error_handler)


@app.exception_handler(pg_errors.ExclusionViolation)
async def overlap_handler(request: Request, exc: pg_errors.ExclusionViolation) -> JSONResponse:
    # Backstop: the database refused an overlapping prefix the application didn't catch first.
    return problem(request, 409, "IPAM-OVERLAP", "The address space overlaps an existing allocation",
                   {"constraint": exc.diag.constraint_name, "dbDetail": exc.diag.message_detail})


@app.exception_handler(pg_errors.IntegrityError)
async def integrity_handler(request: Request, exc: pg_errors.IntegrityError) -> JSONResponse:
    return problem(request, 409, "IPAM-INTEGRITY", "The change breaks a data integrity rule",
                   {"constraint": exc.diag.constraint_name, "dbDetail": exc.diag.message_primary})


@app.exception_handler(RequestValidationError)
async def request_validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return problem(request, 422, "IPAM-REQUEST-INVALID", "Request didn't match the schema", {"errors": exc.errors()})


for r in (auth_routes.router, admin.router, design.router, sites.router, lookups.router, governance.router):
    app.include_router(r, prefix=API_PREFIX)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/ui/"):
        # The UI loads only its own scripts and styles and talks only to this API.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui/")


if settings.web_dir.is_dir():
    app.mount("/ui", StaticFiles(directory=settings.web_dir, html=True), name="ui")
else:
    log.warning("web UI folder %s not found; /ui isn't served", settings.web_dir)
