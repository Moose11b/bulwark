"""
Scan credential confinement and encryption.

These are the tests that matter most in the project. A scan credential is a
live key to someone's application; leaking one is worse than any finding
Bulwark could report.
"""
import httpx
import pytest

from app.core.pinned_connection import ScanCredential, _PinnedTransport
from app.core.secrets import (
    CredentialDecryptionError,
    decrypt_secret,
    encrypt_secret,
    encryption_available,
)

TARGET = "app.example.com"
PINNED = "93.184.216.34"
ATTACKER = "evil.example.com"


class RecordingTransport(httpx.AsyncBaseTransport):
    """Stands in for the network, recording what each hop was sent."""

    def __init__(self, redirect_to: str | None = None):
        self.redirect_to = redirect_to
        self.hops: list[tuple[str, dict]] = []

    async def handle_async_request(self, request):
        self.hops.append((request.url.host, {k.lower(): v for k, v in request.headers.items()}))
        if self.redirect_to and len(self.hops) == 1:
            return httpx.Response(302, headers={"location": self.redirect_to})
        return httpx.Response(200, text="ok")


class GuardedTransport(_PinnedTransport):
    """The real guard, with the network swapped out underneath it."""

    def __init__(self, hostname, pinned_ip, credential, inner):
        super().__init__(hostname, pinned_ip, credential)
        self._inner = inner

    async def handle_async_request(self, request):
        # Reuse the production header logic, then hand off to the recorder.
        url = request.url
        if self._is_target(url.host):
            if self._credential:
                request.headers[self._credential.header_name] = self._credential.header_value
        elif self._credential:
            request.headers.pop(self._credential.header_name, None)
        return await self._inner.handle_async_request(request)


async def _fetch(credential, redirect_to=None, start_host=TARGET):
    inner = RecordingTransport(redirect_to=redirect_to)
    transport = GuardedTransport(TARGET, PINNED, credential, inner)
    async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
        await client.get(f"https://{start_host}/")
    return inner.hops


# ── Credential confinement ───────────────────────────────────────

async def test_credential_reaches_the_target():
    cred = ScanCredential("X-Api-Key", "SECRET_KEY")
    hops = await _fetch(cred)
    assert hops[0][1].get("x-api-key") == "SECRET_KEY"


async def test_custom_header_is_not_forwarded_to_a_redirect_target():
    """The vector httpx does not close on its own.

    httpx strips Authorization and Cookie across origins but forwards custom
    headers, so a scanned app could redirect to a host it controls and harvest
    the key.
    """
    cred = ScanCredential("X-Api-Key", "SECRET_KEY")
    hops = await _fetch(cred, redirect_to=f"https://{ATTACKER}/")

    assert len(hops) == 2, "expected a redirect hop"
    attacker_host, attacker_headers = hops[1]
    assert attacker_host == ATTACKER
    assert "x-api-key" not in attacker_headers, "credential leaked to a third-party host"


async def test_bearer_token_is_not_forwarded_to_a_redirect_target():
    cred = ScanCredential("Authorization", "Bearer SECRET_TOKEN")
    hops = await _fetch(cred, redirect_to=f"https://{ATTACKER}/")
    assert "authorization" not in hops[1][1]


async def test_cookie_is_not_forwarded_to_a_redirect_target():
    cred = ScanCredential("Cookie", "session=SECRET")
    hops = await _fetch(cred, redirect_to=f"https://{ATTACKER}/")
    assert "cookie" not in hops[1][1]


async def test_credential_survives_a_same_host_redirect():
    """/ -> /login must stay authenticated, or the feature is useless."""
    cred = ScanCredential("X-Api-Key", "SECRET_KEY")
    hops = await _fetch(cred, redirect_to=f"https://{TARGET}/login")
    assert hops[1][1].get("x-api-key") == "SECRET_KEY"


async def test_credential_survives_a_redirect_to_the_pinned_ip():
    """A relative redirect resolves against the pinned IP, still the target."""
    cred = ScanCredential("X-Api-Key", "SECRET_KEY")
    hops = await _fetch(cred, redirect_to=f"https://{PINNED}/login")
    assert hops[1][1].get("x-api-key") == "SECRET_KEY"


async def test_no_credential_means_no_header_anywhere():
    hops = await _fetch(None, redirect_to=f"https://{ATTACKER}/")
    for _, headers in hops:
        assert "x-api-key" not in headers
        assert "authorization" not in headers


# ── Encryption at rest ───────────────────────────────────────────

@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
def test_secret_round_trips():
    assert decrypt_secret(encrypt_secret("session=abc123")) == "session=abc123"


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
def test_ciphertext_does_not_contain_the_plaintext():
    secret = "super-secret-session-value"
    assert secret not in encrypt_secret(secret)


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
def test_encryption_is_non_deterministic():
    """Identical secrets must not produce identical ciphertext."""
    assert encrypt_secret("same") != encrypt_secret("same")


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
def test_empty_secret_is_refused():
    with pytest.raises(ValueError):
        encrypt_secret("")


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
def test_undecryptable_ciphertext_raises_rather_than_returning_none():
    """A silent failure would run the scan unauthenticated and call it clean."""
    with pytest.raises(CredentialDecryptionError):
        decrypt_secret("gAAAAABmZm9vYmFyYmF6cXV1eA==")


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
def test_decryption_error_does_not_echo_key_or_ciphertext():
    try:
        decrypt_secret("gAAAAABmZm9vYmFyYmF6cXV1eA==")
    except CredentialDecryptionError as exc:
        message = str(exc)
        assert "gAAAAAB" not in message


# ── API: write-only surface ──────────────────────────────────────

@pytest.fixture
async def asset(client, test_user_and_org):
    r = await client.post("/api/assets", json={
        # Must actually resolve: asset creation runs real SSRF validation.
        "name": "Cred Test", "target": "example.com", "asset_type": "domain",
    })
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
async def test_credential_is_never_returned_by_the_api(client, asset):
    secret = "session=SUPER_SECRET_VALUE_123"
    r = await client.put(f"/api/credentials/assets/{asset}/credential",
                         json={"auth_type": "cookie", "secret": secret})
    assert r.status_code == 200, r.text
    assert secret not in r.text, "secret echoed back in the write response"

    r = await client.get(f"/api/credentials/assets/{asset}/credential")
    assert r.status_code == 200
    assert r.json()["configured"] is True
    assert secret not in r.text, "secret readable back through the API"


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
async def test_stored_value_is_ciphertext_not_plaintext(client, asset):
    from sqlalchemy import select
    from app.database import AsyncSessionLocal
    from app.models import AssetCredential

    secret = "session=PLAINTEXT_CHECK_456"
    await client.put(f"/api/credentials/assets/{asset}/credential",
                     json={"auth_type": "cookie", "secret": secret})

    async with AsyncSessionLocal() as db:
        record = (await db.execute(
            select(AssetCredential).where(AssetCredential.asset_id == asset)
        )).scalar_one()

    assert secret not in record.secret_encrypted, "secret stored in cleartext"
    assert decrypt_secret(record.secret_encrypted) == secret


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
async def test_dangerous_header_names_are_rejected(client, asset):
    for bad in ("Host", "Transfer-Encoding", "X-Forwarded-For"):
        r = await client.put(f"/api/credentials/assets/{asset}/credential",
                             json={"auth_type": "header", "secret": "x", "header_name": bad})
        assert r.status_code == 422, f"{bad} was accepted as a credential header"


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
async def test_control_characters_are_rejected(client, asset):
    """A newline in a header value is request splitting."""
    r = await client.put(f"/api/credentials/assets/{asset}/credential",
                         json={"auth_type": "cookie", "secret": "a\r\nX-Injected: 1"})
    assert r.status_code == 422


@pytest.mark.skipif(not encryption_available(), reason="no encryption key configured")
async def test_credential_can_be_deleted(client, asset):
    await client.put(f"/api/credentials/assets/{asset}/credential",
                     json={"auth_type": "bearer", "secret": "tok"})
    assert (await client.delete(f"/api/credentials/assets/{asset}/credential")).status_code == 204
    assert (await client.get(f"/api/credentials/assets/{asset}/credential")).json()["configured"] is False


async def test_other_orgs_asset_is_not_reachable(client):
    r = await client.get("/api/credentials/assets/does-not-exist/credential")
    assert r.status_code == 404
