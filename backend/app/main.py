from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from app.config import get_settings
from app.core.migrations import run_migrations

settings = get_settings()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("bulwark.startup", version=settings.app_version, env=settings.environment)
    if settings.demo_mode:
        logger.warning(
            "bulwark.demo_mode_enabled",
            detail="Scans may return illustrative sample findings for tools that "
                   "are unavailable. Set DEMO_MODE=false for real assessments.",
        )
    settings.assert_production_safe()
    await run_migrations()
    # First-run local admin (no-op unless local auth mode with an empty user
    # table). Runs after migrations so the users table and its new columns
    # exist.
    from app.core.bootstrap import ensure_bootstrap_admin
    await ensure_bootstrap_admin()
    yield
    logger.info("bulwark.shutdown")
    

app = FastAPI(
    title="Bulwark API",
    description="Fortify · Detect · Defend — Unified cybersecurity defense platform",
    version=settings.app_version,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# ── Security middleware ──────────────────────────────────────────
from app.core.security_middleware import RateLimitMiddleware, SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global error handler ─────────────────────────────────────────
# Catch any unhandled exception so internal details (stack traces,
# library versions, file paths) never leak to clients. The real error
# is logged server-side; the client gets a generic message.
from fastapi import Request as _Request
from fastapi.responses import JSONResponse as _JSONResponse
from starlette.exceptions import HTTPException as _StarletteHTTPException


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: _Request, exc: Exception):
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        error_type=type(exc).__name__,
    )
    return _JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again later."},
    )


# ── Routers ──────────────────────────────────────────────────────
from app.routers import (
    auth, scans, findings, assets, owasp,
    killchain, osint, compliance, reports,
    schedules, alerts, billing, webhooks, admin, threatintel, credentials,
)

app.include_router(auth.router,       prefix="/api/auth",       tags=["Auth"])
app.include_router(scans.router,      prefix="/api/scans",      tags=["Scans"])
app.include_router(findings.router,   prefix="/api/findings",   tags=["Findings"])
app.include_router(assets.router,     prefix="/api/assets",     tags=["Assets"])
app.include_router(owasp.router,      prefix="/api/owasp",      tags=["OWASP"])
app.include_router(killchain.router,  prefix="/api/killchain",  tags=["Kill Chain"])
app.include_router(osint.router,      prefix="/api/osint",      tags=["OSINT"])
app.include_router(compliance.router, prefix="/api/compliance", tags=["Compliance"])
app.include_router(reports.router,    prefix="/api/reports",    tags=["Reports"])
app.include_router(schedules.router,  prefix="/api/schedules",  tags=["Schedules"])
app.include_router(alerts.router,     prefix="/api/alerts",     tags=["Alerts"])
app.include_router(billing.router,    prefix="/api/billing",    tags=["Billing"])
app.include_router(webhooks.router,   prefix="/api/webhooks",   tags=["Webhooks"])
app.include_router(admin.router,      prefix="/api/admin",      tags=["Admin"])
app.include_router(threatintel.router, prefix="/api/threat-intel", tags=["Threat Intel"])
app.include_router(credentials.router, prefix="/api/credentials", tags=["Scan Credentials"])


@app.get("/health", tags=["Health"])
async def health():
    # demo_mode is surfaced so operators and the UI can tell at a glance
    # whether findings may include illustrative sample data.
    return {
        "status": "ok",
        "version": settings.app_version,
        "demo_mode": settings.demo_mode,
    }
