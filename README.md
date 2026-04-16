# KlesLwR License API Worker

Cloudflare Worker that provides secure desktop license verification and internal order fulfillment endpoints.

## Endpoints

- `POST /api/license/verify`
- `GET /api/system/heartbeat`
- `GET /api/status`
- `POST /api/internal/fulfill-order` (Bearer internal token)
- `POST /api/internal/migrate-license` (Bearer internal token)
- `POST /api/internal/archive-events` (Bearer internal token)

## Setup

1. Install dependencies:
   - `npm install`
2. Create `.dev.vars` from `.dev.vars.example` and fill secrets.
3. Set `database_id` in `wrangler.jsonc`.
4. Apply migrations:
   - `npm run db:migrate:remote`
5. Run dev server:
   - `npm run dev`

## Security Model

- License keys are hashed with `LICENSE_PEPPER`.
- HWIDs are hashed with `HWID_PEPPER`.
- Durable Object enforces:
  - nonce replay prevention
  - per-IP/key/hwid rate limiting
- Verify responses include an HMAC proof using `RESPONSE_PROOF_SECRET`.
