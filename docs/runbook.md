# Operational Runbook

Common operational procedures for the Stellar Remittance Platform backend.

**Prerequisites:** SSH access to the server, a copy of the production `.env` file, and `DATABASE_URL` available in your shell.

---

## 1. Server Restart

The backend is a Node.js/Express process started from the `backend/` directory.

```bash
# Find and stop the running process
kill $(lsof -ti tcp:3001)

# Start in the background (production)
cd backend
node src/server.js &

# Or with PM2 (if configured)
pm2 restart future-backend
```

Verify recovery:

```bash
curl -f http://localhost:3001/health
```

Expected response: `{ "status": "ok" }` (or equivalent).

> **Note:** `PORT` defaults to `3001`. If overridden via env, adjust the `lsof` command accordingly.

---

## 2. DB Migration Rollback

The project uses **Prisma**. There is no automatic `migrate down` command; rollback is a two-step process: mark the migration as rolled back, then apply a corrective migration.

**Step 1 — Identify the latest applied migration:**

```bash
cd backend
DATABASE_URL="<value>" npx prisma migrate status
```

Note the name of the last applied migration (e.g. `20240601120000_add_payment_streams`).

**Step 2 — Mark it as rolled back:**

```bash
DATABASE_URL="<value>" npx prisma migrate resolve \
  --rolled-back 20240601120000_add_payment_streams
```

**Step 3 — Apply the corrective schema change:**

Edit `prisma/schema.prisma` to revert the unwanted change, then generate and deploy a new migration:

```bash
DATABASE_URL="<value>" npx prisma migrate deploy
```

> **Warning:** `prisma migrate resolve --rolled-back` only updates Prisma's migration history table. You must also manually reverse any DDL changes (e.g. `DROP COLUMN`) in the database before deploying the corrective migration.

---

## 3. Stream Cancellation

Use the API to cancel a stream so that the event sourcing layer records the cancellation correctly. Cancelling directly in the database skips the `StreamCancelled` event published by the service layer.

**Cancel a single stream by ID:**

```bash
curl -X POST http://localhost:3001/api/v1/streaming/<stream-id>/cancel
```

**List all active streams** (to find IDs that need cancellation):

```bash
curl "http://localhost:3001/api/v1/streaming?senderPublicKey=<GXXX...>"
```

**Bulk-cancel all active streams (emergency only):**

If the API is unavailable, use the Prisma CLI to cancel directly. Be aware this bypasses event publishing.

```bash
cd backend
node --input-type=module <<'EOF'
import prisma from './src/db/client.js';
const { count } = await prisma.paymentStream.updateMany({
  where: { status: 'ACTIVE' },
  data: { status: 'CANCELLED' },
});
console.log(`Cancelled ${count} streams`);
await prisma.$disconnect();
EOF
```

---

## 4. IP Unblock

The rate-limiter whitelist is an **in-memory Set** seeded at startup from the `RATE_LIMIT_WHITELIST` environment variable. There is no persistent store — changes require an env update and a process restart.

**Step 1 — Add the IP to the whitelist in `backend/.env`:**

```bash
# Open .env and append the IP to RATE_LIMIT_WHITELIST (comma-separated)
# Example — before:
RATE_LIMIT_WHITELIST=10.0.0.1

# After:
RATE_LIMIT_WHITELIST=10.0.0.1,203.0.113.42
```

**Step 2 — Restart the backend** (see Section 1) to reload the env.

**Step 3 — Verify the IP is no longer rate-limited:**

```bash
curl -I -H "X-Forwarded-For: 203.0.113.42" http://localhost:3001/health
# Expect HTTP 200, not 429
```

> If `CONFIG_WATCH=true` is set, config file changes reload automatically without a restart — but the whitelist Set is populated at process boot only, so a restart is still required.

---

## 5. Incident Response Protocol

### 5.1 Triage

- [ ] Identify the incident type: `UNAUTHORIZED_ACCESS`, `DATA_BREACH`, `MALWARE_DETECTED`, `DDoS_ATTACK`.
- [ ] Assess severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- [ ] Determine affected systems (e.g. `api`, `database`, `stellar-node`).

### 5.2 Open an Incident Record

```bash
curl -X POST http://localhost:3001/api/v1/security/incidents/create \
  -H "Content-Type: application/json" \
  -d '{
    "type": "UNAUTHORIZED_ACCESS",
    "severity": "CRITICAL",
    "description": "Suspicious login attempts from IP 203.0.113.99",
    "affectedSystems": ["api", "auth"]
  }'
```

Save the returned `id` (e.g. `INC-1719140400000`) for all subsequent updates.

### 5.3 Containment

- [ ] For unauthorized access: revoke active JWT sessions by rotating `JWT_SECRET` in `.env` and restarting the backend.
- [ ] For DDoS: add attacking IPs to `RATE_LIMIT_WHITELIST` **negation** — i.e. do _not_ whitelist them; lower `RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW_MS` as needed, then restart.
- [ ] For a data breach: take the backend offline, preserve logs, and do not alter any files before forensics.

### 5.4 Mark Actions Complete

```bash
# Call for each completed playbook action
curl -X POST http://localhost:3001/api/v1/security/incidents/<INC-ID>/action \
  -H "Content-Type: application/json" \
  -d '{ "action": "Block user account" }'
```

### 5.5 Post-Incident

- [ ] Review `GET /api/v1/security/audit-log` for the affected timeframe.
- [ ] Rotate any compromised secrets (see `backend/CONFIGURATION.md` — Secret rotation).
- [ ] Update `RATE_LIMIT_WHITELIST` or other env vars as needed and redeploy.
- [ ] File a post-mortem within 48 hours.
