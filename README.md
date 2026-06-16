# Warden: A Bitwarden-compatible server for Cloudflare Workers

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy%20to-Cloudflare%20Workers-orange?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

This project provides a self-hosted, Bitwarden-compatible server that runs on Cloudflare Workers, D1, Durable Objects, and optional KV/R2 storage. It is designed to be low-maintenance and serverless, with the important caveat that Cloudflare plan limits, storage choices, traffic, and optional services can affect cost.

## Why another Bitwarden server?

While projects like [Vaultwarden](https://github.com/dani-garcia/vaultwarden) provide excellent self-hosted solutions, they still require you to manage a server or VPS. This can be a hassle, and if you forget to pay for your server, you could lose access to your passwords.

Warden aims to solve this problem by leveraging the Cloudflare Workers ecosystem. By deploying Warden to a Cloudflare Worker and using Cloudflare D1 for storage, you can run a serverless Bitwarden-compatible service without managing a VM. Small personal deployments may fit within Cloudflare free allowances, but R2, higher traffic, storage growth, custom operational needs, or Cloudflare plan changes can require billing.

## Features

* **Core Vault Functionality:** Create, read, update, delete, soft-delete, restore, archive, import, and purge ciphers and folders.
* **File Attachments:** Optional Cloudflare KV or R2 storage for attachments.
* **Bitwarden Send:** Share encrypted text or files via a link. Password-protected Sends are supported; email-based Send access is not.
* **Organization Sharing:** Create organizations, invite members in the database, accept/confirm members, create collections, assign collection access, and share/move ciphers into organization collections.
* **Device and Session Records:** Track Bitwarden client devices, issue refresh tokens, register/clear mobile push tokens for the current device, and rotate the account security stamp to log out all sessions.
* **Live Sync:** Real-time vault updates via WebSocket notifications when `NOTIFY_DO` is configured.
* **Optional Mobile Push:** Mobile push through Bitwarden's push relay when `PUSH_ENABLED=true` and push relay credentials are configured.
* **TOTP Support:** Store TOTP secrets for ciphers and enable authenticator-app login 2FA with recovery codes.
* **Login with Device:** Supports the Bitwarden auth-request flow for known devices.
* **Bitwarden Client Compatibility:** Targets the official Bitwarden clients and the bundled Vaultwarden web vault for the supported feature set.
* **Cloudflare-Native Operations:** Uses Workers Static Assets, D1, Durable Objects, Smart Placement, observability logs, and optional KV/R2 bindings.

### Attachments Support

Warden supports file attachments using either **Cloudflare KV** or **Cloudflare R2** as the storage backend:

| Feature | KV | R2 |
|---------|----|----|  
| Max file size | **25 MB** (KV value limit) | Configured default is 100 MiB; still subject to Worker request and account limits |
| Billing/payment method | Usually not required for basic KV use | May be required depending on your Cloudflare account and R2 usage |
| Streaming I/O | Yes | Yes |

**Backend selection:** R2 takes priority — if R2 is configured, it will be used. Otherwise, KV is used.

See the [deployment guide](docs/deployment.md) for setup details. R2 may incur additional costs; see [Cloudflare R2 pricing](https://developers.cloudflare.com/r2/pricing/).

### Bitwarden Send

- **Text Send:** Enabled by default, no extra configuration required.
- **File Send:** Requires a storage backend (KV or R2), same as [attachments](#attachments-support).

> [!NOTE]
> Due to the D1 single-row size limit of 2 MB, the maximum text Send size is approximately **1.8 MiB**. Additionally, the `/api/sync` endpoint serializes all of the current user's Sends into the response. A large number of Sends or very large text Sends will significantly increase CPU time and response size.


## Current Status

**This project is not yet feature-complete**, ~~and it may never be~~. It supports personal vaults, TOTP, Sends, attachments, and a focused organization/collection sharing surface. Organization support includes organization creation, membership invitation/confirmation, collections, cipher sharing, collection assignment, sync/profile visibility, access checks, and attachment access checks.

It still does **not** support the following advanced Bitwarden features:

* 2FA login providers other than authenticator-app TOTP
* Emergency access
* Outbound email delivery
* Billing, subscriptions, license management, and organization payment flows
* Groups, SCIM, SSO, domain verification, event logging, reports, and enterprise policy enforcement
* WebAuthn/passkeys, Duo, YubiKey, and email-based 2FA
* Full admin-console parity with Bitwarden or Vaultwarden
* Other Bitwarden advanced features

Unsupported enterprise surfaces return disabled or empty compatibility responses where the bundled web vault probes them, so clients can continue to use the supported organization sharing flows without hard 404s.

### Email Delivery

Warden Worker does **not** send email today. There is no SMTP, SES, Resend, SendGrid, Postmark, Mailgun, or other outbound-mail provider integration in this repository.

Email-shaped endpoints are compatibility stubs:

- Registration verification (`/identity/accounts/register/send-verification-email`) returns a fixed mock token and sends no email.
- Password hints (`/api/accounts/password-hint`) never disclose or send the stored hint and return a generic "delivery is not configured" error.
- Organization invites (`/api/organizations/{org_id}/users/invite`) create users or placeholder users plus organization memberships in D1, but no invite email is sent.
- Bitwarden Send email authentication and email-based 2FA are not implemented.

For organization invites, the invited person must be able to register or log in with an address allowed by `ALLOWED_EMAILS`, then complete the web-vault accept/confirm flow. The server-side gate is the allow-list; `DISABLE_USER_REGISTRATION` only affects whether the web vault shows the create-account UI.

## Compatibility

Warden targets the official Bitwarden clients plus the bundled Vaultwarden web vault for supported personal-vault, Send, attachment, TOTP, device, sync, and organization/collection workflows.

The web vault exposes many upstream Bitwarden/Vaultwarden screens that this backend intentionally does not fully implement. Unsupported admin-console and enterprise screens may show empty states, disabled compatibility responses, or explicit "not supported" errors.

## Demo

This fork does not maintain a public demo instance. Deploy your own Worker and configure `ALLOWED_EMAILS` for the accounts or email domains you want to permit.

## Getting Started

- Choose a deployment path: [CLI Deployment](docs/deployment.md#cli-deployment) or [GitHub Actions Deployment](docs/deployment.md#cicd-deployment-with-github-actions).
- Set secrets and optional attachments per the deployment doc.
- Configure Bitwarden clients to point at your worker URL.

## Frontend (Web Vault)

The frontend is bundled with the Worker using [Cloudflare Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/). The GitHub Actions workflows download a **pinned** [bw_web_builds](https://github.com/dani-garcia/bw_web_builds) (Vaultwarden web vault) release (default: `v2026.4.1`) and deploy it together with the backend. You can override it via GitHub Actions Variables (`BW_WEB_VERSION` for prod, `BW_WEB_VERSION_DEV` for dev), or set it to `latest` to follow upstream.

**How it works:**
- Static files (HTML, CSS, JS) are served directly by Cloudflare's edge network.
- API requests (`/api/*`, `/identity/*`, `/notifications/*`) are routed to the Rust Worker.
- No separate Pages deployment or separate frontend domain is needed.

**UI overrides (optional):**
- This project ships a small set of "lightweight self-host" UI tweaks in `public/css/`.
- In CI/CD (and optionally locally), we apply them after extracting `bw_web_builds`:
  - `mkdir -p public/web-vault/css/ && cp public/css/vaultwarden.css public/web-vault/css/`

> [!NOTE]
> Migrating from separate frontend deployment? If you previously deployed the frontend separately to Cloudflare Pages, you can delete the `warden-frontend` Pages project and re-setup the router for the worker. The frontend is now bundled with the Worker and no longer requires a separate deployment.

> [!WARNING]
> The web vault frontend comes from Vaultwarden and therefore exposes many advanced UI features, but most of them are non-functional. See [Current Status](#current-status).

## Configure Custom Domain

The default `*.workers.dev` domain is disabled by default with `workers_dev = false` in `wrangler.toml`. This fork's production configuration uses a Worker custom domain:

```toml
[[routes]]
pattern = "secrets.steppingstonesgroup.dev"
custom_domain = true
```

To deploy under a different domain, update `pattern` to your hostname, make sure the hostname belongs to a Cloudflare zone in the deployment account, and deploy with Wrangler. If you prefer the default Workers domain, set `workers_dev = true` and remove or adjust the custom-domain route.

Cloudflare must proxy the hostname for Worker routing to work. For dashboard-managed setup, use **Workers & Pages** -> your Worker -> **Settings** -> **Domains & Routes**.

## Built-in Rate Limiting

This project includes rate limiting powered by [Cloudflare's Rate Limiting API](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/). Sensitive endpoints are protected:

| Endpoint | Rate Limit | Key Type | Purpose |
|----------|------------|----------|---------|
| `/identity/connect/token` | 5 req/min | Email address | Prevent password brute force |
| `/api/accounts/register` | 5 req/min | IP address | Prevent mass registration & email enumeration |
| `/api/accounts/prelogin` | 5 req/min | IP address | Prevent email enumeration |
| `/api/accounts/password-hint` | 5 req/min | IP address | Slow password-hint probing |
| `/api/auth-requests` | 5 req/min | Email + device + IP | Slow login-with-device prompt spam |
| `/api/sends/access/*` | 5 req/min | Send ID + IP | Slow Send password brute force |
| `/api/devices/knowndevice` | 5 req/min | Email + device + IP | Slow known-device probing |

You can adjust the rate limit settings in `wrangler.toml`:

```toml
[[ratelimits]]
name = "LOGIN_RATE_LIMITER"
namespace_id = "1001"
# Adjust limit (requests) and period (10 or 60 seconds)
simple = { limit = 5, period = 60 }
```

> [!NOTE]
> The `period` must be either `10` or `60` seconds. See [Cloudflare documentation](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) for details.

If the binding is missing, requests proceed without rate limiting (graceful degradation).

## Configuration

### Required Secrets

Set these as Cloudflare Worker secrets, not committed `[vars]`:

* **`ALLOWED_EMAILS`**: Required sign-up allow-list. Supports comma-separated glob patterns such as `ryan@example.com,*@example.org`.
* **`JWT_SECRET`**: Required secret for access-token signing. Use a long random value.
* **`JWT_REFRESH_SECRET`**: Required secret for refresh tokens and upload/download tokens. Use a long random value distinct from `JWT_SECRET`.

### Registration

Server-side account creation is controlled by `ALLOWED_EMAILS`. An email must match one of the configured patterns to register, including users who were pre-created as organization invite placeholders.

`DISABLE_USER_REGISTRATION` controls the web-vault `disableUserRegistration` config flag. When it is unset or truthy, the web vault hides the create-account UI. Setting it to `false` shows the UI, but it does not remove the `ALLOWED_EMAILS` server-side allow-list.

### CPU offloading (via Durable Objects)

Cloudflare Workers have per-request CPU limits, and lower-cost plans are especially sensitive to CPU-heavy work. Two kinds of endpoints are particularly CPU-heavy:

- import endpoint: large JSON payload (typically 500kB–1MB) + parsing + batch inserts.
- registration, login and password verification endpoint: server-side PBKDF2 for password verification.

To keep the main Worker fast while still supporting these operations, Warden can **offload selected endpoints to Durable Objects (DO)**:

- **Heavy DO (`HEAVY_DO`)**: implemented in Rust as `HeavyDo` (reuses the existing axum router) so CPU-heavy endpoints can run with a higher CPU budget.
- **Notify DO (`NOTIFY_DO`)**: powers WebSocket live-sync notifications.

**How to enable/disable**

Whether CPU-heavy endpoints are offloaded is determined by whether the `HEAVY_DO` Durable Object binding is configured in `wrangler.toml`.

> [!NOTE]
> Durable Objects have different CPU limits than normal Worker requests (see [Cloudflare Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/)), so Warden can use them to offload CPU-heavy endpoints.
>
> Durable Objects can incur compute and storage billing. Warden does not intentionally use Durable Object persistent storage for the heavy-route offload path, but you should still review [Cloudflare Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) for your account and traffic profile.
>
> If you choose to disable Durable Objects, CPU-heavy routes may hit Worker CPU limits sooner.

### Smart Placement and Observability

This branch enables Cloudflare Smart Placement in `wrangler.toml`:

```toml
[placement]
mode = "smart"
```

Observability logs are enabled with persisted invocation logs. Traces are configured but disabled by default:

```toml
[observability]
enabled = true

[observability.logs]
enabled = true
persist = true

[observability.traces]
enabled = false
```

### Live Sync and Push Notifications

Warden supports live sync for vault data via two mechanisms: WebSocket push (for desktop apps and browser extensions) and Mobile push notifications (for official mobile apps).

**WebSocket Push (Desktop & Extensions)**

This feature is powered by Durable Objects and enabled by default when the `NOTIFY_DO` Durable Object binding is configured in `wrangler.toml`. Removing this binding (and migration) will gracefully disable WebSocket notifications.

**Mobile Push Notifications**

Warden supports push notifications to official Bitwarden mobile apps via the Bitwarden push relay service.

**Setup:**

1. Obtain an installation ID and key from [https://bitwarden.com/host/](https://bitwarden.com/host/).
2. Store the credentials as secrets (`PUSH_INSTALLATION_ID` & `PUSH_INSTALLATION_KEY`) via the Cloudflare dashboard or `wrangler` cli.
3. Enable push by setting `PUSH_ENABLED` to `true` in `wrangler.toml` `[vars]` or via the Cloudflare dashboard.

Optionally, you can override the default relay endpoints by setting `PUSH_RELAY_URI` and `PUSH_IDENTITY_URI` (defaults to `https://push.bitwarden.com` and `https://identity.bitwarden.com`).

For detailed configuration and troubleshooting, see the [Vaultwarden wiki on push notifications](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-Mobile-Client-push-notification).

### Environment Variables

Configure environment variables in `wrangler.toml` under `[vars]`, or set them via Cloudflare Dashboard:

* **`BASE_URL`** (Optional):
  - Overrides the extracted base URL for up/down URLs for files.
  - Format: Include HTTPS protocol, domain, and port (if using non-443 reverse proxy). Do not include any trailing path.
  - Example: `https://vault.example.com` or `https://vault.example.com:8443`
  - If not set, falls back to extracting from the incoming request.
* **`PASSWORD_ITERATIONS`** (Optional, Default: `600000`):
  - PBKDF2 iterations for server-side password hashing.
  - Minimum is 600000.
* **`TRASH_AUTO_DELETE_DAYS`** (Optional, Default: `30`): 
  - Days to keep soft-deleted items before purge. 
  - Set to `0` or negative to disable.
* **`IMPORT_BATCH_SIZE`** (Optional, Default: `30`): 
  - Batch size for import/delete operations. 
  - `0` disables batching.
* **`DISABLE_USER_REGISTRATION`** (Optional, Default: `true`):
  - Controls the web-vault create-account UI only. Server-side sign-up still requires `ALLOWED_EMAILS`.
* **`AUTHENTICATOR_DISABLE_TIME_DRIFT`** (Optional, Default: `false`): 
  - Set to `true` to disable ±1 time step drift for TOTP validation.
* **`ATTACHMENT_MAX_BYTES`** (Optional): 
  - Max size for individual attachment files. 
  - Example: `104857600` for 100MB.
* **`ATTACHMENT_TOTAL_LIMIT_KB`** (Optional): 
  - Max total attachment storage per user in KB. 
  - Example: `1048576` for 1GB.
* **`ATTACHMENT_TTL_SECS`** (Optional, Default: `300`, Minimum: `60`): 
  - TTL for attachment upload/download URLs.
* **`SEND_TEXT_MAX_BYTES`** (Optional, Default: `1887436` ≈ 1.8 MiB):
  - Max size for text Send content. Constrained by D1's 2 MB single-row limit.
* **`SEND_MAX_BYTES`** (Optional, Default: `104857600` = 100 MiB):
  - Max file size for file Sends. Subject to the same KV/R2 limits as attachments.
* **`USER_SEND_LIMIT_KB`** (Optional):
  - Max total Send file storage per user in KB.
* **`SEND_TTL_SECS`** (Optional, Default: `300`):
  - TTL for Send file upload/download URLs.
* **`ENABLE_UNAUTHENTICATED_KNOWN_DEVICE_LOOKUP`** (Optional, Default: `false`):
  - Set to `true` to preserve the legacy `/api/devices/knowndevice` email/device lookup behavior.
  - Leave unset for the secure default, which returns `false` without revealing stored email/device pairings.

### Scheduled Tasks (Cron)

The worker runs a scheduled task to clean up soft-deleted items. By default, it runs daily at 03:00 UTC (`wrangler.toml` `[triggers]` cron `"0 3 * * *"`). Adjust as needed; see [Cloudflare Cron Triggers documentation](https://developers.cloudflare.com/workers/configuration/cron-triggers/) for cron expression syntax.

## Database Operations

- **Backup & restore:** See [Database Backup & Restore](docs/db-backup-recovery.md#github-actions-backups) for automated backups and manual restoration steps.
- **Time Travel:** See [D1 Time Travel](docs/db-backup-recovery.md#d1-time-travel-point-in-time-recovery) to restore to a point in time.
- **Seeding Global Equivalent Domains (optional):** See [docs/deployment.md](docs/deployment.md) for seeding in CLI deploy and CI/CD.
- **Local dev with D1:**
  - Quick start: `wrangler dev --persist`
  - Full stack (with web vault): download frontend assets as in deployment doc, then `wrangler dev --persist`
  - Import a backup locally: `wrangler d1 execute vault1 --file=backup.sql`
  - Inspect local DB: SQLite file under `.wrangler/state/v3/d1/`

## Local Development with D1

Run the Worker locally with D1 support using Wrangler.

**Quick start (API-only):**

```bash
wrangler dev --persist
```

**Full stack (with Web Vault):**

1. Download the frontend assets (see [deployment doc](docs/deployment.md#download-the-frontend-web-vault)).
2. Start locally:

   ```bash
   wrangler dev --persist
   ```

3. Access the vault at `http://localhost:8787`.

**Using production data temporarily:**

1. Download and decrypt a backup (see [backup doc](docs/db-backup-recovery.md#restoring-database-to-cloudflare-d1)).
2. Import locally without `--remote`:

   ```bash
   wrangler d1 execute vault1 --file=backup.sql
   ```

3. Start `wrangler dev --persist` and point clients to `http://localhost:8787`.

**Inspect local SQLite:**

```bash
ls .wrangler/state/v3/d1/
sqlite3 .wrangler/state/v3/d1/miniflare-D1DatabaseObject/*.sqlite
```

> [!NOTE]
> Local dev requires Node.js and Wrangler. The Worker runs in a simulated environment via [workerd](https://github.com/cloudflare/workerd).

## Updating Your Fork

If you deployed via a GitHub fork, keeping up to date is straightforward:

1. **Watch for new releases** — On [this repository](https://github.com/qaz741wsd856/warden-worker), click **Watch** → **Custom** → check **Releases**. You'll be notified when a new version is published.
2. **Sync your fork** — Go to your fork on GitHub, click **Sync fork** → **Update branch**. This pulls the latest changes from upstream into your fork's default branch.
3. **Automatic deployment** — If you set up CI/CD via GitHub Actions, the push-to-main workflow will automatically build and deploy the new version to your Cloudflare Worker. No manual steps needed.

> [!TIP]
> It is recommended to sync your fork when a new release is published in the upstream, so you always have the latest features and security fixes.

## Contributing

Issues and PRs are welcome. Please run `cargo fmt` and `cargo clippy --target wasm32-unknown-unknown --no-deps` before submitting.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
