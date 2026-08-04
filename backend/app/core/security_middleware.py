"""
Security middleware: rate limiting + response security headers.

Rate limiting uses a Redis sliding-window counter keyed by client IP and a
route bucket, so scan-launch and auth endpoints can have tighter limits than
read endpoints. Falls back to allowing the request if Redis is unavailable
(fail-open) rather than taking the whole API down.
"""
import time
import structlog
import redis.asyncio as aioredis
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# Per-bucket limits: (max_requests, window_seconds)
RATE_LIMITS = {
    "scan_launch": (10, 60),     # 10 scan launches per minute
    "auth":        (20, 60),     # 20 auth calls per minute
    "write":       (60, 60),     # 60 writes per minute
    "default":     (120, 60),    # 120 reads per minute
}


def _bucket_for(request: Request) -> str:
    path = request.url.path
    method = request.method
    if path.startswith("/api/scans") and method == "POST":
        return "scan_launch"
    if path.startswith("/api/assets") and path.endswith("/scan"):
        return "scan_launch"
    if path.startswith("/api/auth") or path.startswith("/api/webhooks"):
        return "auth"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "write"
    return "default"


def _client_ip(request: Request) -> str:
    # Respect X-Forwarded-For when behind a trusted proxy (first hop)
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            try:
                self._redis = aioredis.from_url(settings.redis_url)
            except Exception:
                self._redis = None
        return self._redis

    async def dispatch(self, request: Request, call_next):
        # Skip health checks and docs
        if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        bucket = _bucket_for(request)
        max_req, window = RATE_LIMITS.get(bucket, RATE_LIMITS["default"])
        ip = _client_ip(request)
        key = f"ratelimit:{bucket}:{ip}"

        r = await self._get_redis()
        if r is not None:
            try:
                now = time.time()
                # Sliding window via sorted set
                async with r.pipeline(transaction=True) as pipe:
                    pipe.zremrangebyscore(key, 0, now - window)
                    pipe.zadd(key, {str(now): now})
                    pipe.zcard(key)
                    pipe.expire(key, window)
                    results = await pipe.execute()
                count = results[2]

                if count > max_req:
                    logger.warning("ratelimit.exceeded", ip=ip, bucket=bucket, count=count)
                    return JSONResponse(
                        status_code=429,
                        content={
                            "detail": f"Rate limit exceeded. Max {max_req} requests "
                                      f"per {window}s for this endpoint.",
                        },
                        headers={"Retry-After": str(window)},
                    )
            except Exception as e:
                # Fail open — don't break the API if Redis hiccups
                logger.debug("ratelimit.redis_error", error=str(e))

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add defensive HTTP response headers to every API response."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        # Strip server identification
        response.headers["Server"] = "Bulwark"
        return response
