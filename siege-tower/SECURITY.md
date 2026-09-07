# Siege Tower — Security

Siege Tower plans and documents authorized engagements. It never executes a
command, launches a tool, or connects to a target, and it never reads or moves
data from a client's systems — the planning engine is a dependency-free package
with no network or subprocess access. Everything below hardens the *web/server
tier* and the data it stores (client names, in-scope targets, authorization
references, operator names, notes, evidence references).

## Security model

| Control | How |
| --- | --- |
| **Authentication** | Bearer tokens. `POST /api/auth/login` returns a token; every `/api` route except `/api/health` and login requires `Authorization: Bearer <token>`. Only a SHA-256 hash of each token is stored. Sessions expire (sliding, default 12h) and are revoked on logout and on password change. |
| **No CSRF surface** | Auth rides on a header, not a cookie, so there is no cross-site request forgery vector. |
| **Multi-tenancy** | Every user belongs to an organization. All engagement queries are scoped by `org_id` in the data layer — a caller can only ever see its own tenant's data. |
| **Authorization** | Roles `admin` > `operator` > `viewer`. Viewers are read-only; operators manage engagements; admins manage users, view the audit log, and can hard-delete. |
| **Passwords** | PBKDF2-HMAC-SHA256 (600k rounds, per-user salt), constant-time verify, minimum 12 characters. |
| **Encryption at rest** | The engagement blob is encrypted with Fernet (AES-128-CBC + HMAC) when `SIEGE_ENCRYPTION_KEY` is set. Without a key the app runs but logs a prominent warning and stores plaintext. |
| **Input validation** | All request bodies are typed, length-bounded Pydantic models; unknown fields are ignored (no mass assignment). Request bodies over `SIEGE_MAX_BODY_BYTES` (default 1 MiB) are rejected with 413. |
| **Rate limiting** | Login is limited per IP+username (10 / 5 min); the API per IP (600 / min). In-process — front hosted/multi-worker deployments with a shared limiter. |
| **Transport** | The server refuses to bind a non-loopback interface over plaintext HTTP unless TLS is configured (or `SIEGE_ALLOW_INSECURE=1` for a trusted private network). Serve TLS directly or behind an HTTPS proxy (`SIEGE_BEHIND_TLS=1` enables HSTS). |
| **Security headers** | Strict CSP (`script-src 'self'` — the UI ships external JS, no inline script), plus `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, and `Cache-Control: no-store` on API responses. |
| **Audit log** | Append-only record of logins (success and failure), logout, password changes, user management, and engagement create/update/delete/purge — with actor, org, target, IP, and timestamp. Admins read it at `GET /api/audit`. |
| **Retention** | Deletes are soft (the row is retained with a `deleted_at` stamp). Hard erasure is an admin-only, audited `DELETE /api/engagements/{id}/purge`. |
| **Error handling** | Unhandled errors return a generic 500; details are logged server-side only. |

## First run

On an empty database the app creates one organization and one admin user so the
app is usable but never open:

- Set `SIEGE_ADMIN_USERNAME` / `SIEGE_ADMIN_PASSWORD` to choose the credentials, or
- leave `SIEGE_ADMIN_PASSWORD` unset and a strong password is generated and
  printed **once** to the server log. Change it after first login.

## Configuration (environment)

| Variable | Purpose | Default |
| --- | --- | --- |
| `SIEGE_ENCRYPTION_KEY` | Fernet key for at-rest encryption. Generate with `python -m server.security keygen`. | *(none — plaintext, with a warning)* |
| `SIEGE_ADMIN_USERNAME` / `SIEGE_ADMIN_PASSWORD` | First-run admin. | `admin` / *(generated)* |
| `SIEGE_ORG_NAME` | First-run organization name. | `Default` |
| `SIEGE_SESSION_TTL_HOURS` | Session lifetime. | `12` |
| `SIEGE_MAX_BODY_BYTES` | Max request body size. | `1048576` |
| `SIEGE_HOST` / `SIEGE_PORT` | Bind address / port. | `127.0.0.1` / `8000` |
| `SIEGE_TLS_CERT` / `SIEGE_TLS_KEY` | Serve HTTPS directly. | *(none)* |
| `SIEGE_BEHIND_TLS` | Set to `1` when TLS is terminated upstream (enables HSTS). | *(unset)* |
| `SIEGE_ALLOW_INSECURE` | Set to `1` to allow a non-loopback bind without TLS (trusted networks only). | *(unset)* |
| `SIEGE_TRUST_PROXY` | Set to `1` to trust `X-Forwarded-For` for client IP (only behind a known proxy). | *(unset)* |
| `SIEGE_DB` | SQLite path. | `siege.db` next to the app |

## Deployment checklist

1. Generate and set `SIEGE_ENCRYPTION_KEY`; store it in a secrets manager, not in
   the repo. Losing it makes existing encrypted engagements unreadable.
2. Set a strong `SIEGE_ADMIN_PASSWORD` (or capture the generated one) and change
   it after first login.
3. Terminate TLS (directly or via a reverse proxy) for any non-loopback use;
   set `SIEGE_BEHIND_TLS=1` behind a proxy.
4. Restrict `siege.db` file permissions (0600) and encrypt backups.
5. For multi-worker/hosted deployments, add a shared rate limiter and consider
   moving persistence to a managed database.

## Reporting a vulnerability

Please open a private report to the maintainers rather than a public issue.
