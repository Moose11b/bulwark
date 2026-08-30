from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ─────────────────────────────────────────────────────
    app_name: str = "Bulwark"
    app_version: str = "2.0.0"
    environment: str = "development"
    debug: bool = False
    secret_key: str = "change-me-in-production"
    allowed_origins: str = "http://localhost:3000"

    # Demo mode replaces unavailable scanners with illustrative sample
    # findings so the platform can be shown without the full toolchain or any
    # API keys. It is OFF by default and must be switched on deliberately:
    # with it off, Bulwark only ever reports what it actually observed.
    demo_mode: bool = False

    # ── Authentication mode ─────────────────────────────────────
    # How the platform authenticates dashboard/API users:
    #   local  — built-in email/password (self-contained; the default for a
    #            fresh self-hosted install, so `docker compose up` just works)
    #   oidc   — your own OIDC provider (Keycloak, Authentik, Authelia, ...)
    #   clerk  — Clerk-hosted auth (best for a managed/hosted deployment)
    #   auto   — infer: oidc if OIDC_ISSUER set, else clerk if Clerk keys set,
    #            else local. Keeps existing deployments working unchanged.
    auth_mode: str = "auto"

    # First-run local admin. On first startup in local mode with an empty user
    # table, an admin is created. If no password is set here, a strong random
    # one is generated and logged once; either way the first login must change
    # it. Never leave a real password in a committed .env.
    bootstrap_admin_email: str = "admin@bulwark.local"
    bootstrap_admin_password: str = ""

    # Lifetime of a local-auth session token.
    local_session_ttl_hours: int = 12

    # ── Database ────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://bulwark:changeme@localhost:5432/bulwark"

    # ── Redis ───────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Celery ──────────────────────────────────────────────────
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # ── Clerk ───────────────────────────────────────────────────
    clerk_secret_key: str = ""
    clerk_publishable_key: str = ""
    clerk_webhook_secret: str = ""
    # Explicit trusted Clerk issuer (https://<subdomain>.clerk.accounts.dev).
    # Normally derived from the publishable key; set only to override.
    clerk_issuer: str = ""

    # ── Generic OIDC (self-hosted auth) ─────────────────────────
    # An alternative to Clerk for self-hosters running their own IdP
    # (Keycloak, Authentik, Authelia, ...). Set the issuer to enable it.
    oidc_issuer: str = ""              # e.g. https://id.example.com/realms/main
    oidc_client_id: str = ""           # expected `aud` on incoming tokens
    # Create a user on first valid login rather than requiring pre-provisioning.
    oidc_auto_provision: bool = False
    # Org that auto-provisioned users join, by slug. Created if absent.
    oidc_default_org_slug: str = "default"
    oidc_default_org_name: str = "Default Organisation"
    oidc_default_role: str = "analyst"

    # ── Stripe ──────────────────────────────────────────────────
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_starter_price_id: str = ""
    stripe_pro_price_id: str = ""
    stripe_enterprise_price_id: str = ""

    # ── External APIs ───────────────────────────────────────────
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    hibp_api_key: str = ""
    alienvault_api_key: str = ""
    nvd_api_key: str = ""

    # ── Alerts ──────────────────────────────────────────────────
    slack_webhook_url: str = ""
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@bulwark.dev"

    # ── Scan credentials ────────────────────────────────────────
    # Fernet key (urlsafe base64, 32 bytes) encrypting stored scan
    # credentials. Unset means authenticated scanning is disabled — the API
    # refuses to accept credentials rather than storing them in cleartext.
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    credential_encryption_key: str = ""

    # ── Scanning ────────────────────────────────────────────────
    # How many scanner stages may run against a target at once. Stages are
    # independent, so raising this shortens a FULL scan — but every active
    # scanner points at the same host, so this is also how hard Bulwark hits
    # someone's server. 4 reaches the practical floor (the slowest single
    # scanner) without turning a scan into a load test.
    scan_stage_concurrency: int = 4

    # ── Scan limits per plan ────────────────────────────────────
    starter_scan_limit: int = 25
    pro_scan_limit: int = 250
    enterprise_scan_limit: int = 99999

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    @property
    def clerk_issuer_url(self) -> str | None:
        """The one trusted Clerk issuer, or None if Clerk is not configured.

        Prefer the explicit override; otherwise derive it from the publishable
        key, which encodes the frontend-API host as base64. Deriving it means
        existing deployments gain issuer pinning with no new required config —
        and pinning is what closes the forge-any-issuer bypass.
        """
        if self.clerk_issuer:
            return self.clerk_issuer.rstrip("/")

        key = self.clerk_publishable_key.strip()
        for prefix in ("pk_test_", "pk_live_"):
            if key.startswith(prefix):
                import base64
                encoded = key[len(prefix):]
                try:
                    # Tolerate missing base64 padding.
                    decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4))
                    host = decoded.decode("utf-8").rstrip("$").rstrip("/")
                    if host:
                        return f"https://{host}"
                except Exception:
                    return None
        return None

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer)

    @property
    def effective_auth_mode(self) -> str:
        """Resolve 'auto' to a concrete mode; otherwise return the explicit one.

        Inference preserves the behaviour of existing deployments: a config
        that set OIDC or Clerk keys keeps using them. A brand-new install with
        neither falls through to local, so it works out of the box.
        """
        mode = (self.auth_mode or "auto").lower()
        if mode != "auto":
            return mode
        if self.oidc_issuer:
            return "oidc"
        if self.clerk_secret_key or self.clerk_publishable_key:
            return "clerk"
        return "local"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def assert_production_safe(self) -> None:
        """Refuse to run in production with insecure placeholder values."""
        if not self.is_production:
            return
        problems = []
        if self.debug:
            problems.append("DEBUG must be false in production")
        if "change" in self.secret_key.lower() or len(self.secret_key) < 32:
            problems.append("SECRET_KEY must be a strong unique value (>=32 chars)")
        # Only require a provider's secret when that provider is the active
        # auth mode — a local-auth deployment needs neither Clerk nor Stripe.
        mode = self.effective_auth_mode
        if mode == "clerk" and (
            not self.clerk_secret_key or "changeme" in self.clerk_secret_key.lower()
        ):
            problems.append("CLERK_SECRET_KEY is not configured")
        if mode == "local" and self.bootstrap_admin_password and (
            "changeme" in self.bootstrap_admin_password.lower()
            or len(self.bootstrap_admin_password) < 10
        ):
            problems.append("BOOTSTRAP_ADMIN_PASSWORD is weak (>=10 chars, not a placeholder)")
        if "changeme" in self.database_url.lower():
            problems.append("Database password is still the default 'changeme'")
        if "changeme" in self.redis_url.lower():
            problems.append("Redis password is still the default 'changeme'")
        if problems:
            raise RuntimeError(
                "Refusing to start in production with insecure config:\n  - "
                + "\n  - ".join(problems)
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
