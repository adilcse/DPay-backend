# DPay Backend Service

The centralized bank ledger, cryptographic certificate authority, and offline settlement engine for **DPay** — the hardware-secured offline digital cash system.

---

## Key Features

- **Offline Cash Note Minting**: Issues cryptographically signed, bearer cash notes backed by Android Keystore hardware keys (TEE / StrongBox).
- **5-Day Spend Leases**: Signs rotating 5-day wallet leases with cryptographic ledger commitments to prevent long-term detached double spending.
- **Peer-to-Peer Offline Settlement**: Atomically verifies transferred offline notes, credits receivers, returns change to payers, and detects hardware compromise / double spends.
- **PostgreSQL Database & Sequelize ORM**: Durable, ACID-compliant relational ledger with atomic savepoint transactions.
- **Redis Cache & Fast Storage**: Sub-millisecond session authentication, OTP challenge caching, single-use attestation challenge consumption, and high-speed fraud blocklists.
- **Production-Ready & Hardened Core**: Hardware attestation, 5-day leases, Canonical CBOR note issuing, atomic double-spend isolation, and sanitized error handling.
- **Central Bank Simulator (RBI Liquidity Gateway)**: Built-in Central Bank clearing simulator allowing unlimited simulated funds (`POST /v1/bank/load` or `/v1/central-bank/load`), automated shortfall funding on offline note generation, and withdrawal/settlement sweeps (`POST /v1/bank/withdraw`). *Per architecture requirements, this is the only faked component; all other backend APIs and services are 100% production-ready.*

---

## Architecture Overview

```
                      ┌──────────────────────────┐
                      │    DPay Android App      │
                      └────────────┬─────────────┘
                                   │ HTTPS / REST
                                   ▼
                      ┌──────────────────────────┐
                      │    Express 5 Gateway     │
                      │   (Validation & Auth)    │
                      └──────┬────────────┬──────┘
                             │            │
            ┌────────────────┴───┐    ┌───┴────────────────┐
            │   PostgreSQL 16    │    │      Redis 7       │
            │   Sequelize ORM    │    │ (Sessions, Cache,  │
            │ (Ledger & Wallets) │    │  Rate Limits, OTP) │
            └────────────────────┘    └────────────────────┘
```

For deep technical details, cryptographic message formats (CBOR, P-256), and sequence diagrams, see the [Backend Design Document](./docs/BACKEND_DESIGN.md).

---

## Prerequisites

- **Node.js**: `>= 22.13.0`
- **PostgreSQL**: `>= 16`
- **Redis**: `>= 7`
- **Docker** (optional, recommended for local database & cache setup)

---

## Quickstart

### 1. Launch PostgreSQL and Redis via Docker

```bash
# PostgreSQL container
docker run -d --name dpay-postgres -p 5432:5432 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=dpay \
  postgres:16

# Redis container
docker run -d --name dpay-redis -p 6379:6379 redis:7
```

### 2. Configure Environment

Create or edit `.env` in the `Dpay-backend` root:

```env
# Database (either DATABASE_URL or individual DB_* properties)
DATABASE_URL=postgres://postgres:postgres@localhost:5432/dpay
# DB_USER=postgres
# DB_PASSWORD=postgres
# DATABASE=dpay
# DB_HOST=127.0.0.1
# DB_PORT=5432

# Redis
REDIS_URL=redis://127.0.0.1:6379

# Mock Bank & Infinite Money
MOCK_BANK_NAME=DPay Reserve Bank
MOCK_BANK_IFSC=DPAY0000001
MOCK_BANK_INFINITE_MONEY=true
MOCK_BANK_AUTO_LOAD=true

# Server
PORT=8080
HOST=0.0.0.0
NODE_ENV=development
LOG_LEVEL=info

# Admin
ADMIN_API_KEY=dev-admin-secret-key-0123456789
```

### 3. Install Dependencies & Run

```bash
# Install dependencies
npm install

# Start in development mode with live watch
npm run dev
```

The server automatically initializes all Sequelize tables on boot and listens on `http://localhost:8080`.

---

## Scripts Reference

| Command | Description |
|---|---|
| `npm run dev` | Runs the server in development mode using Node 22 native type stripping and hot-reloading (`--watch`). |
| `npm test` | Runs the full test suite (35 unit & integration tests across 12 test suites) against PostgreSQL and Redis. |
| `npm run typecheck` | Validates TypeScript types across the codebase with `tsc --noEmit`. |
| `npm run build` | Compiles TypeScript source to production JavaScript in `./dist`. |
| `npm start` | Launches the compiled production server from `./dist/index.js`. |
| `npm run gen:issuer-key` | Generates a new P-256 PEM key for production note and certificate signing. |

---

## Interactive Swagger & OpenAPI Documentation

The backend serves complete interactive Swagger documentation with built-in API testing:

- **Interactive Swagger UI**: [`http://localhost:8080/docs`](http://localhost:8080/docs) (or [`/api-docs`](http://localhost:8080/api-docs))
- **OpenAPI 3.1 Spec (JSON)**: [`http://localhost:8080/docs/openapi.json`](http://localhost:8080/docs/openapi.json) or [`docs/openapi.json`](./docs/openapi.json)
- **OpenAPI 3.1 Spec (YAML)**: [`http://localhost:8080/docs/openapi.yaml`](http://localhost:8080/docs/openapi.yaml) or [`docs/openapi.yaml`](./docs/openapi.yaml)

You can import `docs/openapi.yaml` directly into Postman, Insomnia, Swagger Editor, or any OpenAPI code generator (OpenAPI Generator, Kiota, Orval, etc.).

---

## API Endpoints Reference

All requests and responses use JSON. Authenticated endpoints require `Authorization: Bearer <session_token>`.

### 1. Authentication
- `POST /v1/auth/otp` — Request an SMS OTP code (`{ phone: "+919876543210" }`).
- `POST /v1/auth/otp/verify` — Verify the code and acquire a session token (`{ phone, code, deviceId }`).
- `POST /v1/auth/logout` — Invalidate the session across Redis and PostgreSQL.

### 2. User & Handles
- `GET /v1/handles/availability?handle=asha.rao` — Check if a UPI-style handle is available.
- `GET /v1/handles/suggestion?fullName=Asha%20Rao` — Suggests available handles based on user's name.
- `POST /v1/profile` — Register full name and handle (automatically provisions linked Mock Bank account).
- `GET /v1/profile` — Fetch profile details.
- `PATCH /v1/profile` — Update name or email.
- `POST /v1/device/move` — Binds account to a new phone and revokes old device sessions.

### 3. Wallet Provisioning & Leases
- `POST /v1/provisioning/challenge` — Generates a 16-byte single-use attestation challenge.
- `POST /v1/wallet/certificate` — Submits identity key attestation; returns bank-signed wallet certificate.
- `POST /v1/wallet/notes` — Debits online balance, mints note certificates, and issues a 5-day lease.
- `POST /v1/wallet/lease` — Refreshes the 5-day wallet lease for currently unspent notes.
- `GET /v1/wallet` — Inspects active wallet status, held notes, and remaining offline load limit.

### 4. Settlement & Balances
- `POST /v1/settlement` — Batch uploads offline payments (sent or received). Credits receiver and refunds change to payer.
- `GET /v1/payments/:paymentId` — Queries the settlement status of an individual payment.
- `GET /v1/account` — Online balance and outstanding offline note totals.
- `GET /v1/transactions` — Cursor-paginated online double-entry ledger history.
- `GET /v1/blocklist` — List of wallets blocked due to cryptographic proof of double spending.

### 5. Central Bank Simulator (Infinite Money)
*(Mounted at both `/v1/bank` and `/v1/central-bank`)*
- `GET /v1/bank/account` or `GET /v1/central-bank/account` — View linked central bank details (account number, IFSC, infinite money status, balance).
- `POST /v1/bank/load` or `POST /v1/central-bank/load` — Load money from central bank into DPay online balance (`{ amountPaise: 500000 }`).
- `POST /v1/bank/withdraw` or `POST /v1/central-bank/withdraw` — Settle/withdraw online funds back to central bank account (`{ amountPaise: 200000 }`).
- `GET /v1/bank/transactions` or `GET /v1/central-bank/transactions` — Transaction log of central bank loads and settlement sweeps.

### 6. Administration
*(Protected with `X-Admin-Key` header)*
- `POST /v1/admin/accounts/:phone/credit` — Manual balance top-up.
- `POST /v1/admin/accounts/:phone/freeze` — Freezes account and revokes lease issuance.
- `POST /v1/admin/accounts/:phone/unfreeze` — Unfreezes account.
- `GET /v1/admin/fraud-events` — Inspects detected double-spend incidents.
- `POST /v1/admin/maintenance` — Triggers expired note refunds and session cleanup.

### 7. Health & Production Probes
- `GET /health` — Liveness check: returns 200 `{ status: "ok", service: "dpay-backend", uptimeSeconds }`.
- `GET /health/ready` — Readiness check: verifies PostgreSQL, Redis, and Issuer key signing capability; returns 200 when ready or 503 if any dependency is down.

---

## Mock Bank & Infinite Money Workflow

To test the system without connecting to a real payment gateway:

1. **Check Linked Account**:
   ```bash
   curl -H "Authorization: Bearer $SESSION" http://localhost:8080/v1/bank/account
   ```
2. **Load Online Balance**:
   ```bash
   curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
     -d '{"amountPaise": 1000000}' \
     http://localhost:8080/v1/bank/load
   ```
3. **Auto-Fund on Load**:
   With `MOCK_BANK_AUTO_LOAD=true`, loading ₹5,000 onto an offline device wallet will automatically draw from the Mock Bank if the online balance is insufficient.
4. **Withdrawal / Settlement Payout**:
   When received offline payments are settled online, sweep the proceeds back to the bank:
   ```bash
   curl -X POST -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
     -d '{"amountPaise": 500000}' \
     http://localhost:8080/v1/bank/withdraw
   ```

---

## Security & Verification

- **Strict Canonical CBOR**: All binary protocols use canonical CBOR (RFC 8949) with deterministic key ordering.
- **Hardware Key Attestation**: In production (`ATTESTATION_MODE=enforce`), notes and wallet keys are validated against Google root certificates.
- **Double-Spend Prevention**: Offline payments are signed by single-use hardware keys. Uploading duplicate spends provides cryptographic proof of hardware compromise, instantly freezing the payer across the entire network.

---

## License

Private and proprietary. Part of the DPay offline digital payment suite.

