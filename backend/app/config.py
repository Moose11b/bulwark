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
        for name, val in [
            ("CLERK_SECRET_KEY", self.clerk_secret_key),
            ("STRIPE_SECRET_KEY", self.stripe_secret_key),
        ]:
            if not val or "changeme" in val.lower():
                problems.append(f"{name} is not configured")
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
