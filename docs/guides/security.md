# Security Best Practices for Platform Integrators

This guide covers the security topics most relevant to developers building on or integrating with the FuTuRe Remittance Platform.

---

## API Key Storage

Never embed API keys or JWT secrets in source code or version-controlled files.

- Store credentials in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).
- Use `.env` files only for local development; exclude them via `.gitignore`.
- Rotate API keys immediately if they are accidentally committed. Treat any published key as compromised, even if the commit is reverted — Git history and CI logs may retain it.
- Apply the principle of least privilege: issue keys with only the permissions the integration needs.

---

## Webhook Signature Verification

All outbound webhooks from FuTuRe include an `X-FuTuRe-Signature: sha256=<hex>` header. You must verify this before processing the payload.

```javascript
import { createHmac, timingSafeEqual } from 'crypto';

function verifyWebhookSignature(rawBody, signatureHeader, secret) {
  const expected = createHmac('sha256', secret)
    .update(rawBody) // raw Buffer or string — do NOT parse as JSON first
    .digest('hex');
  const received = signatureHeader?.replace('sha256=', '') ?? '';

  // Use constant-time comparison to prevent timing attacks
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(received, 'hex'));
}
```

**Key points:**

- Always use `timingSafeEqual` — a regular `===` comparison leaks information via response timing.
- Verify the raw request body _before_ JSON parsing; any middleware that mutates `req.body` will break the signature.
- Reject requests with a missing or malformed signature header with `401`.
- Rotate webhook secrets via `PATCH /api/webhooks/{id}/rotate-secret`. The previous secret stays valid for 24 hours to allow a rolling update.

---

## Private Key Management

The platform generates Stellar keypairs on behalf of users. Integrators that handle keys directly must follow these rules.

- **Never log or store raw secret keys.** Use the encrypted-secret format (`ENC(<base64>)`) provided by `backend/src/config/secrets.js`.
- Keep the `CONFIG_ENCRYPTION_KEY` / `STREAM_SECRET_ENCRYPTION_KEY` out of application code; inject them at runtime.
- Prefer non-custodial flows where the private key never leaves the user's browser. If you must hold keys server-side, encrypt them at rest with AES-256-GCM and a per-user derived key.
- Never use real Stellar mainnet keys in development or CI environments. The testnet is reset periodically; treat any testnet key as disposable.

---

## CSP Configuration

A Content Security Policy (CSP) limits what resources a browser will load. The platform sets a default CSP in `backend/src/middleware/securityHeaders.js`. When embedding the frontend or building your own UI on top of the API, configure CSP headers to:

- Restrict `script-src` to your own origin and any explicitly trusted CDNs.
- Set `default-src 'self'` and allow additional origins only where necessary.
- Use `connect-src` to whitelist the API origin rather than allowing `*`.
- Avoid `unsafe-inline` and `unsafe-eval`; use a nonce or hash-based approach for any inline scripts.

Test your CSP with the [CSP Evaluator](https://csp-evaluator.withgoogle.com/) before deploying.

---

## Known Attack Vectors

### Replay Attacks

Webhook and API requests are susceptible to replay if an attacker captures a valid signed request and resends it.

**Mitigations:**

- Include a monotonically increasing nonce or a short-lived timestamp in every signed payload.
- Reject requests with a timestamp older than ±5 minutes.
- Maintain a short-lived nonce cache (e.g., in Redis) to reject duplicate nonces within the replay window.

### Front-Running

On public blockchains, pending transactions are visible before they are confirmed. An attacker can observe a large payment and submit their own transaction with a higher fee to execute first.

**Mitigations:**

- Use Stellar's transaction `timeBounds` (`minTime` / `maxTime`) to expire transactions that are not confirmed promptly.
- For high-value flows, consider breaking a single large transfer into smaller sequential transactions.
- Avoid broadcasting transaction details publicly before submission.

### Rate-Limit Bypass

Clients that cycle IP addresses or forge headers can circumvent IP-based rate limits.

**Mitigations:**

- Prefer user-account-level rate limiting over IP-level limits for authenticated endpoints.
- Validate the `X-Forwarded-For` header only when behind a known, trusted proxy. The platform uses `getClientIP()` (`backend/src/middleware/rateLimiter.js`) to handle this safely.
- Apply exponential back-off on repeated failures rather than a fixed lockout window to resist DoS amplification.

### SQL / NoSQL Injection

The platform uses Prisma with parameterised queries. Avoid raw SQL via `$queryRaw` / `$executeRaw` unless absolutely necessary; if you must, use tagged template literals (Prisma automatically parameterises them):

```javascript
// Safe — Prisma parameterises the interpolated value
const rows = await prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${userId}`;

// Unsafe — never do this
const rows = await prisma.$queryRaw(`SELECT * FROM "User" WHERE id = '${userId}'`);
```

---

## Reporting Vulnerabilities

If you discover a security issue, please report it privately to the maintainers before public disclosure. Open a GitHub Security Advisory rather than a public issue so the team can coordinate a fix.
