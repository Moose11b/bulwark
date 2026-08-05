"""
Generic OIDC token verification.

Lets a self-hosted Bulwark authenticate against any standards-compliant OIDC
provider (Keycloak, Authentik, Authelia, ...) instead of Clerk, so it can run
without a dependency on an external SaaS.

The security-critical rule, shared with the Clerk path: a token is only ever
verified against an issuer the operator configured. The issuer is NEVER taken
from the token to decide who to trust — that is the bypass this whole module
exists to avoid. The `iss` claim is only checked for equality against the
already-trusted issuer.
"""
import httpx
import structlog
from jose import jwt, JWTError

logger = structlog.get_logger()

# Discovery documents and JWKS are cached per issuer. Keyed by the trusted
# issuer URL, which comes from config, not from any token.
_discovery_cache: dict[str, dict] = {}
_jwks_cache: dict[str, dict] = {}


async def _discover(issuer: str) -> dict:
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        doc = resp.json()
    _discovery_cache[issuer] = doc
    return doc


async def _jwks(issuer: str, *, force: bool = False) -> dict:
    if not force and issuer in _jwks_cache:
        return _jwks_cache[issuer]
    doc = await _discover(issuer)
    jwks_uri = doc.get("jwks_uri")
    if not jwks_uri:
        raise ValueError("OIDC discovery document has no jwks_uri")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        keys = resp.json()
    _jwks_cache[issuer] = keys
    return keys


async def verify_oidc_token(token: str, *, issuer: str, audience: str | None) -> dict:
    """Verify a token against a TRUSTED issuer and return its claims.

    `issuer` and `audience` come from configuration. The token's own `iss` is
    only accepted if it equals the trusted `issuer`; its signature must be made
    by a key published at that issuer's JWKS endpoint.

    Raises JWTError on any failure — callers translate that to a 401.
    """
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except JWTError:
        raise

    keys = await _jwks(issuer)
    signing_key = next((k for k in keys.get("keys", []) if k.get("kid") == kid), None)
    if signing_key is None:
        # Keys rotate; refetch once before giving up.
        keys = await _jwks(issuer, force=True)
        signing_key = next((k for k in keys.get("keys", []) if k.get("kid") == kid), None)
    if signing_key is None:
        raise JWTError("No matching signing key for token")

    # verify_aud is enabled only when an audience is configured; many IdPs put
    # the client id in `aud`, some in `azp`. Requiring it when set is the
    # stronger posture.
    options = {"verify_aud": audience is not None}
    return jwt.decode(
        token,
        signing_key,
        algorithms=[signing_key.get("alg", "RS256")],
        issuer=issuer,
        audience=audience,
        options=options,
    )
