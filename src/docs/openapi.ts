import YAML from 'yaml';

export const openApiSpec: Record<string, any> = {
  openapi: '3.1.0',
  info: {
    title: 'DPay Backend API (Hardware-Secured Offline Digital Cash & Bank Rails)',
    version: '1.0.0',
    description: `## Overview
DPay is an offline-first peer-to-peer digital payments system designed to enable real-world monetary exchange without cellular or internet connectivity at point-of-sale.

The **DPay Backend** acts as:
1. **Central Bank Clearing Simulator**: Provides infinite fiat liquidity (\`/v1/bank\` and \`/v1/central-bank\`), simulated bank accounts, and settlement sweeps. *Note: This is the ONLY simulated component in the backend.*
2. **Cryptographic Certificate Authority**: Issues hardware-bound bearer cash notes (Canonical CBOR, NIST P-256) and rotating 5-day wallet spend leases.
3. **Double-Entry Ledger**: Real-time accounts denominated in integer paise (\`1 INR = 100 paise\`) with non-negative constraints.
4. **Offline Settlement Engine**: Verifies offline transferred notes, credits receivers, refunds change to payers, and detects hardware compromise / double spends.
5. **Fast Storage & Ephemeral Security**: Redis-accelerated sub-millisecond session authentication, OTP caching, single-use challenge consumption, and high-speed fraud blocklists.

---

### Data Formats & Conventions
- **Monetary Amounts**: Denominated in **integer paise** (\`100 paise = ₹1.00\`). Floats/decimals are strictly forbidden. Example: \`500000\` = ₹5,000.00.
- **Binary Fields**: Encoded as standard base64 strings with padding (RFC 4648). Includes certificates, challenges, public keys, and CBOR payments.
- **Public Keys**: 33-byte compressed NIST P-256 public keys (\`02\` or \`03\` prefix + 32-byte X-coordinate), base64-encoded.
- **Timestamps**: UNIX epoch timestamps in **seconds** (integer).
- **Authentication**: Bearer tokens via \`Authorization: Bearer <sessionToken>\`.
- **Administration**: Admin endpoints require \`X-Admin-Key: <adminApiKey>\`.
`,
    contact: {
      name: 'DPay Engineering Team',
      url: 'https://github.com/qbitlog/dpay',
    },
    license: {
      name: 'Proprietary',
    },
  },
  servers: [
    {
      url: 'https://dpay.cohortnest.com',
      description: 'Production server',
    },
    {
      url: 'http://localhost:8080',
      description: 'Local development server',
    },
  ],
  tags: [
    { name: 'Health', description: 'Liveness and dependency readiness health checks' },
    { name: 'Authentication', description: 'Phone OTP request, verification, and session management' },
    { name: 'Handles & Profile', description: 'UPI-style handles (@dpay), user registration, and profile updates' },
    { name: 'Device Management', description: 'Device binding and migration to new hardware' },
    { name: 'Wallet & Provisioning', description: 'Hardware key attestation, note certificates, and 5-day leases' },
    { name: 'Settlement & Account', description: 'Batch offline payment settlement, transactions, and fraud blocklists' },
    { name: 'Central Bank (Simulator)', description: 'Faked Central Bank (RBI / Interbank Clearing): Infinite money loading and settlement sweeps' },
    { name: 'Administration', description: 'Back-office administrative actions, account freezes, and fraud inspection' },
  ],
  paths: {
    '/health': {
      get: {
        tags: ['Health'],
        summary: 'Liveness check probe',
        description: 'Returns HTTP 200 if the backend process is up and listening.',
        responses: {
          '200': {
            description: 'Process is alive',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HealthLivenessResponse' },
              },
            },
          },
        },
      },
    },
    '/health/ready': {
      get: {
        tags: ['Health'],
        summary: 'Readiness check probe',
        description: 'Deep health check validating PostgreSQL connectivity, Redis ping, and Issuer signing key readiness.',
        responses: {
          '200': {
            description: 'All backend subsystems are healthy and ready to serve traffic',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HealthReadinessResponse' },
              },
            },
          },
          '503': {
            description: 'One or more backend dependencies are down or degraded',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HealthReadinessResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/trust-anchors': {
      get: {
        tags: ['Wallet & Provisioning'],
        summary: 'Get bank trust anchor public keys',
        description: 'Returns the pinned P-256 public keys used by the bank to sign note certificates and wallet leases.',
        responses: {
          '200': {
            description: 'List of trust anchors',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TrustAnchorsResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/auth/otp': {
      post: {
        tags: ['Authentication'],
        summary: 'Request Phone OTP',
        description: 'Sends a 6-digit verification code to the given Indian mobile phone number. In non-production environments with debug codes enabled, the response includes `debugCode`.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/OtpRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'OTP issued successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/OtpRequestResponse' },
              },
            },
          },
          '400': {
            description: 'Invalid phone format',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '429': {
            description: 'Resend too soon or rate limit exceeded',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/auth/otp/verify': {
      post: {
        tags: ['Authentication'],
        summary: 'Verify OTP & Acquire Session',
        description: 'Verifies the 6-digit OTP code. On success, creates a session token in Redis and PostgreSQL and returns whether the profile is registered.',
        parameters: [
          {
            name: 'X-Device-Id',
            in: 'header',
            required: false,
            description: 'Client device ID (if not provided in body)',
            schema: { type: 'string' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/OtpVerifyRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'OTP verified, session token issued',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/OtpVerifyResponse' },
              },
            },
          },
          '401': {
            description: 'Invalid OTP code',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '410': {
            description: 'OTP expired',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '423': {
            description: 'OTP locked due to too many failed attempts',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/auth/logout': {
      post: {
        tags: ['Authentication'],
        summary: 'Logout & Invalidate Session',
        description: 'Revokes the active bearer session token across both Redis and PostgreSQL.',
        security: [{ BearerAuth: [] }],
        responses: {
          '204': { description: 'Session revoked successfully' },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
        },
      },
    },
    '/v1/handles/availability': {
      get: {
        tags: ['Handles & Profile'],
        summary: 'Check handle availability',
        description: 'Checks whether a given UPI-style handle (e.g. `asha.rao` or `asha.rao@dpay`) is available for registration.',
        parameters: [
          {
            name: 'handle',
            in: 'query',
            required: true,
            description: 'The handle to check',
            schema: { type: 'string', example: 'asha.rao' },
          },
        ],
        responses: {
          '200': {
            description: 'Availability status',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HandleAvailabilityResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/handles/suggestion': {
      get: {
        tags: ['Handles & Profile'],
        summary: 'Suggest available handle from name',
        description: 'Derives clean handle candidates from the user\'s full name and returns the first available handle.',
        parameters: [
          {
            name: 'fullName',
            in: 'query',
            required: true,
            description: 'User full name',
            schema: { type: 'string', example: 'Asha Rao' },
          },
        ],
        responses: {
          '200': {
            description: 'Suggested handle',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HandleSuggestionResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/profile': {
      post: {
        tags: ['Handles & Profile'],
        summary: 'Register User Profile',
        description: 'Creates a new user profile after successful OTP authentication. Automatically provisions a linked Central Bank account with infinite liquidity.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ProfileRegisterRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Profile created successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ProfileResponse' },
              },
            },
          },
          '409': {
            description: 'Account already registered or handle taken',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
      get: {
        tags: ['Handles & Profile'],
        summary: 'Get Profile',
        description: 'Retrieves current account profile information.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'User profile details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ProfileResponse' },
              },
            },
          },
          '404': {
            description: 'Account not yet registered',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
      patch: {
        tags: ['Handles & Profile'],
        summary: 'Update Profile',
        description: 'Updates full name or email address.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ProfileUpdateRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Updated profile',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ProfileResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/device/move': {
      post: {
        tags: ['Device Management'],
        summary: 'Move Account to This Device',
        description: 'Binds account to the calling session\'s device ID, revoking all sessions and active wallet leases associated with the previous device.',
        security: [{ BearerAuth: [] }],
        responses: {
          '204': { description: 'Device migrated successfully' },
        },
      },
    },
    '/v1/provisioning/challenge': {
      post: {
        tags: ['Wallet & Provisioning'],
        summary: 'Request Attestation Challenge',
        description: 'Generates a 16-byte single-use cryptographic challenge for hardware key attestation. Challenge is cached in Redis with a 5-minute TTL and consumed atomically via GETDEL.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Challenge generated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ProvisioningChallengeResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/wallet': {
      get: {
        tags: ['Wallet & Provisioning'],
        summary: 'Inspect Wallet Status',
        description: 'Returns active wallet information, outstanding notes, remaining offline load capacity, security tier (TEE / StrongBox), and active 5-day lease.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Current wallet status',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/WalletStatusResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/wallet/certificate': {
      post: {
        tags: ['Wallet & Provisioning'],
        summary: 'Certify Hardware Wallet Key',
        description: 'Verifies the hardware identity key attestation chain (and Play Integrity token in enforce mode). Issues a bank-signed P-256 wallet certificate.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CertifyWalletRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Wallet certified successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CertifyWalletResponse' },
              },
            },
          },
          '422': {
            description: 'Attestation verification failed or integrity token invalid',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/wallet/notes': {
      post: {
        tags: ['Wallet & Provisioning'],
        summary: 'Issue Offline Cash Notes & 5-Day Lease',
        description: 'Debits online balance (or auto-funds shortfall from Central Bank Simulator if infinite money auto-load is on), signs one bearer note certificate per key according to DenominationPlanner, and issues a fresh 5-day lease.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/IssueNotesRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Notes and 5-day lease issued',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/IssueNotesResponse' },
              },
            },
          },
          '400': {
            description: 'Denominations do not match DenominationPlanner or invalid challenge',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '422': {
            description: 'Insufficient balance (when auto-load is off) or exceeds ₹5,000 cap',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/wallet/lease': {
      post: {
        tags: ['Wallet & Provisioning'],
        summary: 'Refresh 5-Day Wallet Lease',
        description: 'Extends offline spending authority by issuing a new 5-day lease with an incremented sequence number and a cryptographic ledger digest over active unspent notes.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Lease refreshed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RefreshLeaseResponse' },
              },
            },
          },
          '403': {
            description: 'Wallet or account is frozen',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/settlement': {
      post: {
        tags: ['Settlement & Account'],
        summary: 'Batch Offline Payment Settlement',
        description: 'Uploads batch of offline payments (sent or received). Atomically verifies Canonical CBOR payloads, checks 5-day payer leases, marks notes spent, credits receiver online balance, and refunds change to payer.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/SettlementUploadRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Settlement report',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SettlementReportResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/payments/{paymentId}': {
      get: {
        tags: ['Settlement & Account'],
        summary: 'Query Payment Settlement Status',
        description: 'Queries settlement status of an individual payment by its 16-byte ID (hex or base64url).',
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'paymentId',
            in: 'path',
            required: true,
            description: '16-byte payment ID in hex (32 chars) or base64url (22 chars)',
            schema: { type: 'string', example: 'e3b0c44298fc1c149afbf4c8996fb924' },
          },
        ],
        responses: {
          '200': {
            description: 'Payment status',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PaymentStatusResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/account': {
      get: {
        tags: ['Settlement & Account'],
        summary: 'Get Account Balances',
        description: 'Returns available online ledger balance and total value of currently outstanding offline cash notes.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Account balance summary',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AccountSummaryResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/transactions': {
      get: {
        tags: ['Settlement & Account'],
        summary: 'Paginated Ledger Transactions',
        description: 'Cursor-paginated double-entry ledger history of all balance modifications (loads, settled payments, change refunds, expired note returns).',
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'limit',
            in: 'query',
            required: false,
            description: 'Number of entries to return (default 50, max 100)',
            schema: { type: 'integer', default: 50, minimum: 1, maximum: 100 },
          },
          {
            name: 'before',
            in: 'query',
            required: false,
            description: 'Cursor: return entries with ID less than this value',
            schema: { type: 'integer' },
          },
        ],
        responses: {
          '200': {
            description: 'Ledger entries',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LedgerTransactionsResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/blocklist': {
      get: {
        tags: ['Settlement & Account'],
        summary: 'Get Double-Spending Blocklist',
        description: 'Returns list of wallet IDs permanently quarantined due to cryptographic proof of double spending.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Blocked wallet IDs',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BlocklistResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/bank/account': {
      get: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Get Linked Central Bank Account',
        description: 'Returns linked Central Bank account details (account number, IFSC, infinite money status, balance). Also accessible at `/v1/central-bank/account`.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Central bank details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankDetailsResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/central-bank/account': {
      get: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Get Linked Central Bank Account (Alias)',
        description: 'Explicit Central Bank alias for `/v1/bank/account`.',
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Central bank details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankDetailsResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/bank/load': {
      post: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Load Money from Central Bank (Infinite Money)',
        description: 'Transfers money from the Central Bank account into the user\'s online DPay balance. Guaranteed to succeed under infinite money semantics.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BankLoadRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Money loaded successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankLoadResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/central-bank/load': {
      post: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Load Money from Central Bank (Alias)',
        description: 'Explicit Central Bank alias for `/v1/bank/load`.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BankLoadRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Money loaded successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankLoadResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/bank/withdraw': {
      post: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Withdraw Online Balance to Central Bank',
        description: 'Sweeps/withdraws funds from the DPay online balance back into the Central Bank account.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BankWithdrawRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Withdrawal completed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankWithdrawResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/central-bank/withdraw': {
      post: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Withdraw Online Balance to Central Bank (Alias)',
        description: 'Explicit Central Bank alias for `/v1/bank/withdraw`.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BankWithdrawRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Withdrawal completed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankWithdrawResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/bank/transactions': {
      get: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Central Bank Transaction Log',
        description: 'Lists all Central Bank clearing transactions (loads, auto-loads, withdrawal sweeps).',
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'limit',
            in: 'query',
            required: false,
            schema: { type: 'integer', default: 50, minimum: 1, maximum: 100 },
          },
        ],
        responses: {
          '200': {
            description: 'Bank transaction history',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankTransactionsResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/central-bank/transactions': {
      get: {
        tags: ['Central Bank (Simulator)'],
        summary: 'Central Bank Transaction Log (Alias)',
        description: 'Explicit Central Bank alias for `/v1/bank/transactions`.',
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'limit',
            in: 'query',
            required: false,
            schema: { type: 'integer', default: 50, minimum: 1, maximum: 100 },
          },
        ],
        responses: {
          '200': {
            description: 'Bank transaction history',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/BankTransactionsResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/admin/accounts/{phone}/credit': {
      post: {
        tags: ['Administration'],
        summary: 'Admin Credit Online Balance',
        description: 'Back-office administrative balance top-up for an account.',
        security: [{ AdminKeyAuth: [] }],
        parameters: [
          {
            name: 'phone',
            in: 'path',
            required: true,
            schema: { type: 'string', example: '9876543210' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/AdminCreditRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Account credited',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminCreditResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/admin/accounts/{phone}/freeze': {
      post: {
        tags: ['Administration'],
        summary: 'Freeze Account',
        description: 'Prevents account from issuing new notes or receiving 5-day leases.',
        security: [{ AdminKeyAuth: [] }],
        parameters: [
          {
            name: 'phone',
            in: 'path',
            required: true,
            schema: { type: 'string', example: '9876543210' },
          },
        ],
        responses: {
          '200': {
            description: 'Account frozen',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminFreezeResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/admin/accounts/{phone}/unfreeze': {
      post: {
        tags: ['Administration'],
        summary: 'Unfreeze Account',
        description: 'Restores normal note and lease issuing capabilities.',
        security: [{ AdminKeyAuth: [] }],
        parameters: [
          {
            name: 'phone',
            in: 'path',
            required: true,
            schema: { type: 'string', example: '9876543210' },
          },
        ],
        responses: {
          '200': {
            description: 'Account unfrozen',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminFreezeResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/admin/fraud-events': {
      get: {
        tags: ['Administration'],
        summary: 'List Detected Fraud Events',
        description: 'Returns detected double-spend attempts, offending wallet IDs, and compromised note serials.',
        security: [{ AdminKeyAuth: [] }],
        parameters: [
          {
            name: 'limit',
            in: 'query',
            required: false,
            schema: { type: 'integer', default: 100, minimum: 1, maximum: 500 },
          },
        ],
        responses: {
          '200': {
            description: 'Fraud events log',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AdminFraudEventsResponse' },
              },
            },
          },
        },
      },
    },
    '/v1/admin/maintenance': {
      post: {
        tags: ['Administration'],
        summary: 'Trigger Maintenance Tasks',
        description: 'Runs expired note refunds and session cleanup immediately.',
        security: [{ AdminKeyAuth: [] }],
        responses: {
          '200': {
            description: 'Maintenance completed',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    refundedNotes: { type: 'integer', example: 0 },
                    cleanedSessions: { type: 'integer', example: 1 },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'Token',
        description: 'Session bearer token acquired from `/v1/auth/otp/verify`. Provide in header as `Authorization: Bearer <token>`.',
      },
      AdminKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-Admin-Key',
        description: 'Back-office API key configured via `ADMIN_API_KEY`.',
      },
    },
    schemas: {
      ErrorResponse: {
        type: 'object',
        required: ['error'],
        properties: {
          error: {
            type: 'object',
            required: ['code', 'message'],
            properties: {
              code: {
                type: 'string',
                enum: [
                  'INVALID_PHONE',
                  'INVALID_OTP',
                  'OTP_EXPIRED',
                  'OTP_LOCKED',
                  'RESEND_TOO_SOON',
                  'NOT_AUTHENTICATED',
                  'INVALID_HANDLE',
                  'HANDLE_TAKEN',
                  'ACCOUNT_EXISTS',
                  'INVALID_CHALLENGE',
                  'WALLET_NOT_PROVISIONED',
                  'INSUFFICIENT_BALANCE',
                  'LIMIT_EXCEEDED',
                  'INVALID_DENOMINATIONS',
                  'WALLET_FROZEN',
                  'DEVICE_MOVED',
                  'INVALID_REQUEST',
                  'ACCOUNT_NOT_REGISTERED',
                  'ATTESTATION_FAILED',
                  'RATE_LIMITED',
                  'FORBIDDEN',
                  'NOT_FOUND',
                  'SERVICE_UNAVAILABLE',
                  'INTERNAL',
                ],
                example: 'INVALID_REQUEST',
              },
              message: { type: 'string', example: 'request validation failed' },
              details: { type: 'object', additionalProperties: true },
            },
          },
        },
      },
      OtpRequest: {
        type: 'object',
        required: ['phone'],
        properties: {
          phone: {
            type: 'string',
            description: 'Indian mobile number in 10-digit or +91 format',
            example: '+919876543210',
          },
        },
      },
      OtpRequestResponse: {
        type: 'object',
        required: ['phone', 'resendAt', 'expiresAt'],
        properties: {
          phone: { type: 'string', example: '9876543210' },
          resendAt: { type: 'integer', description: 'Epoch seconds when next OTP may be requested', example: 1730000030 },
          expiresAt: { type: 'integer', description: 'Epoch seconds when this OTP expires', example: 1730000300 },
          debugCode: { type: 'string', description: 'Available in dev mode when EXPOSE_DEBUG_OTP=true', example: '123456' },
        },
      },
      OtpVerifyRequest: {
        type: 'object',
        required: ['phone', 'code'],
        properties: {
          phone: { type: 'string', example: '+919876543210' },
          code: { type: 'string', pattern: '^\\d{6}$', example: '123456' },
          deviceId: { type: 'string', minLength: 8, maxLength: 128, example: 'pixel-8-pro-device-uuid' },
        },
      },
      OtpVerifyResponse: {
        type: 'object',
        required: ['session', 'registered', 'expiresAt'],
        properties: {
          session: { type: 'string', description: 'Opaque bearer session token', example: '5f9b4c2a1e0d...' },
          registered: { type: 'boolean', description: 'Whether the user has completed profile setup', example: true },
          expiresAt: { type: 'integer', description: 'Epoch seconds when session expires', example: 1732592000 },
        },
      },
      HandleAvailabilityResponse: {
        type: 'object',
        required: ['handle', 'available'],
        properties: {
          handle: { type: 'string', example: 'asha.rao' },
          available: { type: 'boolean', example: true },
        },
      },
      HandleSuggestionResponse: {
        type: 'object',
        required: ['suggestion'],
        properties: {
          suggestion: { type: 'string', example: 'asharao' },
        },
      },
      ProfileRegisterRequest: {
        type: 'object',
        required: ['fullName', 'handle'],
        properties: {
          fullName: { type: 'string', minLength: 1, maxLength: 100, example: 'Asha Rao' },
          handle: { type: 'string', maxLength: 40, example: 'asha.rao' },
          email: { type: 'string', format: 'email', nullable: true, example: 'asha.rao@example.com' },
        },
      },
      ProfileResponse: {
        type: 'object',
        required: ['id', 'phone', 'fullName', 'handle', 'createdAt'],
        properties: {
          id: { type: 'string', format: 'uuid', example: 'c0a80101-0000-0000-0000-000000000001' },
          phone: { type: 'string', example: '9876543210' },
          fullName: { type: 'string', example: 'Asha Rao' },
          handle: { type: 'string', example: 'asha.rao@dpay' },
          email: { type: 'string', nullable: true, example: 'asha.rao@example.com' },
          boundDeviceId: { type: 'string', nullable: true, example: 'pixel-8-pro-device-uuid' },
          frozen: { type: 'boolean', example: false },
          createdAt: { type: 'integer', example: 1730000000 },
          updatedAt: { type: 'integer', example: 1730000000 },
        },
      },
      ProfileUpdateRequest: {
        type: 'object',
        required: ['fullName'],
        properties: {
          fullName: { type: 'string', minLength: 1, maxLength: 100, example: 'Asha Rao Sharma' },
          email: { type: 'string', format: 'email', nullable: true, example: 'asha.sharma@example.com' },
        },
      },
      ProvisioningChallengeResponse: {
        type: 'object',
        required: ['challenge', 'expiresAt'],
        properties: {
          challenge: { type: 'string', description: '16-byte random challenge, base64 encoded', example: 'q83vflzVqU+w1Q4X5o...' },
          expiresAt: { type: 'integer', description: 'Challenge expiration timestamp (epoch seconds)', example: 1730000300 },
        },
      },
      KeyAttestation: {
        type: 'object',
        required: ['publicKey', 'attestationChain'],
        properties: {
          alias: { type: 'string', description: 'Client Keystore alias (ignored by server)', example: 'dpay_identity' },
          publicKey: { type: 'string', description: '33-byte compressed P-256 public key in base64', example: 'Ams2d81V4V...' },
          attestationChain: {
            type: 'array',
            items: { type: 'string', description: 'X.509 certificate DER bytes in base64' },
          },
        },
      },
      CertifyWalletRequest: {
        type: 'object',
        required: ['challenge', 'identity'],
        properties: {
          challenge: { type: 'string', description: '16-byte base64 challenge' },
          identity: { $ref: '#/components/schemas/KeyAttestation' },
          integrityToken: { type: 'string', description: 'Google Play Integrity token (required when PLAY_INTEGRITY_MODE=enforce)' },
        },
      },
      CertifyWalletResponse: {
        type: 'object',
        required: ['walletCertificate', 'walletId', 'securityLevel', 'offlineLimitPaise'],
        properties: {
          walletCertificate: { type: 'string', description: 'Canonical CBOR wallet certificate signed by bank issuer key, base64 encoded' },
          walletId: { type: 'string', description: '16-byte wallet ID, base64 encoded' },
          securityLevel: { type: 'string', enum: ['TEE', 'STRONGBOX', 'SOFTWARE'], example: 'STRONGBOX' },
          offlineLimitPaise: { type: 'integer', description: 'Maximum offline balance limit in paise (e.g. 500000 for ₹5,000)', example: 500000 },
        },
      },
      IssueNotesRequest: {
        type: 'object',
        required: ['challenge', 'values', 'keys'],
        properties: {
          challenge: { type: 'string', description: '16-byte base64 challenge' },
          values: {
            type: 'array',
            items: { type: 'integer' },
            description: 'Array of note denominations in paise matching DenominationPlanner.plan',
            example: [100000, 100000, 100000, 50000, 50000, 20000, 20000, 20000, 10000, 10000, 9000, 5000, 2000, 2000, 2000],
          },
          keys: {
            type: 'array',
            items: { $ref: '#/components/schemas/KeyAttestation' },
            description: 'Array of hardware note keys matching the values array',
          },
        },
      },
      IssueNotesResponse: {
        type: 'object',
        required: ['noteCertificates', 'lease', 'sequence', 'issuedAt', 'notAfter', 'outstandingValuePaise', 'outstandingNoteIds'],
        properties: {
          noteCertificates: {
            type: 'array',
            items: { type: 'string' },
            description: 'Array of base64-encoded CBOR note certificates signed by bank',
          },
          lease: { type: 'string', description: 'Base64-encoded CBOR 5-day wallet lease' },
          sequence: { type: 'integer', description: 'Monotonically increasing lease sequence number', example: 1 },
          issuedAt: { type: 'integer', example: 1730000000 },
          notAfter: { type: 'integer', description: 'Epoch seconds when lease expires (5 days from issue)', example: 1730432000 },
          outstandingValuePaise: { type: 'integer', example: 500000 },
          outstandingNoteIds: {
            type: 'array',
            items: { type: 'string' },
            description: 'Base64 note IDs covered by this lease',
          },
        },
      },
      RefreshLeaseResponse: {
        type: 'object',
        required: ['lease', 'sequence', 'issuedAt', 'notAfter', 'outstandingValuePaise', 'outstandingNoteIds'],
        properties: {
          lease: { type: 'string', description: 'Fresh base64-encoded CBOR 5-day wallet lease' },
          sequence: { type: 'integer', example: 2 },
          issuedAt: { type: 'integer', example: 1730086400 },
          notAfter: { type: 'integer', example: 1730518400 },
          outstandingValuePaise: { type: 'integer', example: 500000 },
          outstandingNoteIds: { type: 'array', items: { type: 'string' } },
        },
      },
      WalletStatusResponse: {
        type: 'object',
        required: ['provisioned', 'boundToThisDevice'],
        properties: {
          provisioned: { type: 'boolean', example: true },
          boundToThisDevice: { type: 'boolean', example: true },
          walletId: { type: 'string', example: 'q72v...' },
          displayName: { type: 'string', example: 'asha.rao@dpay' },
          walletCertificate: { type: 'string' },
          certificateNotAfter: { type: 'integer', example: 1761500000 },
          securityLevel: { type: 'string', example: 'STRONGBOX' },
          integrityTier: { type: 'string', example: 'STRONG' },
          frozen: { type: 'boolean', example: false },
          offlineLimitPaise: { type: 'integer', example: 500000 },
          outstandingValuePaise: { type: 'integer', example: 500000 },
          remainingLoadCapacityPaise: { type: 'integer', example: 0 },
          lease: {
            type: 'object',
            nullable: true,
            properties: {
              sequence: { type: 'integer', example: 1 },
              issuedAt: { type: 'integer', example: 1730000000 },
              notAfter: { type: 'integer', example: 1730432000 },
            },
          },
          notes: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                noteId: { type: 'string' },
                valuePaise: { type: 'integer', example: 100000 },
                notAfter: { type: 'integer', example: 1731209600 },
                status: { type: 'string', enum: ['OUTSTANDING', 'SPENT', 'REFUNDED', 'EXPIRED'], example: 'OUTSTANDING' },
                refundAt: { type: 'integer', nullable: true, example: 1731814400 },
              },
            },
          },
        },
      },
      SettlementUploadRequest: {
        type: 'object',
        required: [],
        properties: {
          received: {
            type: 'array',
            items: {
              type: 'object',
              required: ['payment', 'receivedAt'],
              properties: {
                payment: { type: 'string', description: 'Base64-encoded CBOR Payment wire bytes' },
                receivedAt: { type: 'integer', description: 'Receiver clock epoch seconds' },
              },
            },
            default: [],
          },
          sent: {
            type: 'array',
            items: { type: 'string', description: 'Base64-encoded CBOR Payment wire bytes' },
            default: [],
          },
        },
      },
      SettlementReportResponse: {
        type: 'object',
        required: [
          'settledReceived',
          'settledSent',
          'rejectedReceived',
          'rejectedSent',
          'rejections',
          'creditedPaise',
          'refundedPaise',
          'onlineBalancePaise',
        ],
        properties: {
          settledReceived: { type: 'array', items: { type: 'string' } },
          settledSent: { type: 'array', items: { type: 'string' } },
          rejectedReceived: { type: 'array', items: { type: 'string' } },
          rejectedSent: { type: 'array', items: { type: 'string' } },
          rejections: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                direction: { type: 'string', enum: ['received', 'sent'] },
                index: { type: 'integer' },
                paymentId: { type: 'string', nullable: true },
                code: {
                  type: 'string',
                  enum: [
                    'INVALID_PAYMENT',
                    'NOT_YOUR_PAYMENT',
                    'UNKNOWN_WALLET',
                    'UNKNOWN_NOTE',
                    'NOTE_REFUNDED',
                    'DOUBLE_SPEND',
                    'PAYMENT_ID_CONFLICT',
                    'BAD_RECEIVE_TIME',
                  ],
                },
                reason: { type: 'string' },
              },
            },
          },
          creditedPaise: { type: 'integer', description: 'Total paise credited to receiver online balance', example: 25000 },
          refundedPaise: { type: 'integer', description: 'Total paise returned to payer as change', example: 5000 },
          onlineBalancePaise: { type: 'integer', description: 'New online balance after settlement', example: 75000 },
        },
      },
      PaymentStatusResponse: {
        type: 'object',
        required: ['paymentId', 'status'],
        properties: {
          paymentId: { type: 'string' },
          status: { type: 'string', enum: ['PENDING', 'SETTLED', 'REJECTED'], example: 'SETTLED' },
          amountPaise: { type: 'integer', example: 25000 },
          changePaise: { type: 'integer', example: 5000 },
          settledAt: { type: 'integer', example: 1730005000 },
        },
      },
      AccountSummaryResponse: {
        type: 'object',
        required: ['onlineBalancePaise', 'offlineOutstandingPaise'],
        properties: {
          onlineBalancePaise: { type: 'integer', example: 150000 },
          offlineOutstandingPaise: { type: 'integer', example: 350000 },
        },
      },
      LedgerTransactionsResponse: {
        type: 'object',
        required: ['entries', 'nextCursor'],
        properties: {
          entries: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'integer', example: 101 },
                kind: {
                  type: 'string',
                  enum: [
                    'OPENING_CREDIT',
                    'OFFLINE_LOAD',
                    'PAYMENT_RECEIVED',
                    'PAYMENT_CHANGE_REFUND',
                    'NOTE_EXPIRY_REFUND',
                    'ADMIN_CREDIT',
                    'BANK_LOAD',
                    'BANK_WITHDRAW',
                    'BANK_AUTO_LOAD',
                  ],
                  example: 'BANK_LOAD',
                },
                amountPaise: { type: 'integer', example: 500000 },
                balanceAfterPaise: { type: 'integer', example: 500000 },
                paymentId: { type: 'string', nullable: true },
                noteId: { type: 'string', nullable: true },
                createdAt: { type: 'integer', example: 1730000000 },
              },
            },
          },
          nextCursor: { type: 'integer', nullable: true, example: 51 },
        },
      },
      BlocklistResponse: {
        type: 'object',
        required: ['walletIds', 'updatedAt'],
        properties: {
          walletIds: { type: 'array', items: { type: 'string' } },
          updatedAt: { type: 'integer', example: 1730001000 },
        },
      },
      TrustAnchorsResponse: {
        type: 'object',
        required: ['issuers'],
        properties: {
          issuers: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                keyId: { type: 'integer', example: 1 },
                publicKey: { type: 'string', description: 'Compressed P-256 public key (base64)' },
              },
            },
          },
        },
      },
      BankDetailsResponse: {
        type: 'object',
        required: ['bankName', 'accountNumber', 'ifsc', 'upiVpa', 'infiniteMoney', 'bankBalancePaise', 'onlineBalancePaise'],
        properties: {
          bankName: { type: 'string', example: 'DPay Reserve Bank' },
          accountNumber: { type: 'string', example: '1009876543210' },
          ifsc: { type: 'string', example: 'DPAY0000001' },
          upiVpa: { type: 'string', example: 'asha.rao@mockbank' },
          infiniteMoney: { type: 'boolean', example: true },
          bankBalancePaise: { type: 'integer', example: 10000000000 },
          onlineBalancePaise: { type: 'integer', example: 2500000 },
        },
      },
      BankLoadRequest: {
        type: 'object',
        required: ['amountPaise'],
        properties: {
          amountPaise: { type: 'integer', minimum: 1, maximum: 10000000000, example: 500000 },
          reference: { type: 'string', maxLength: 100, example: 'CLI-LOAD-01' },
        },
      },
      BankLoadResponse: {
        type: 'object',
        required: ['success', 'amountPaise', 'newOnlineBalancePaise', 'bankRef', 'message'],
        properties: {
          success: { type: 'boolean', example: true },
          amountPaise: { type: 'integer', example: 500000 },
          newOnlineBalancePaise: { type: 'integer', example: 3000000 },
          bankRef: { type: 'string', example: 'MB-LOAD-7A9B1C2D' },
          message: { type: 'string', example: 'Loaded ₹5,000.00 from DPay Reserve Bank' },
        },
      },
      BankWithdrawRequest: {
        type: 'object',
        required: ['amountPaise'],
        properties: {
          amountPaise: { type: 'integer', minimum: 1, maximum: 10000000000, example: 200000 },
          reference: { type: 'string', maxLength: 100, example: 'CLI-WITHDRAW-01' },
        },
      },
      BankWithdrawResponse: {
        type: 'object',
        required: ['success', 'amountPaise', 'remainingOnlineBalancePaise', 'bankRef', 'message'],
        properties: {
          success: { type: 'boolean', example: true },
          amountPaise: { type: 'integer', example: 200000 },
          remainingOnlineBalancePaise: { type: 'integer', example: 2800000 },
          bankRef: { type: 'string', example: 'MB-SWEEP-8F3E4D1A' },
          message: { type: 'string', example: 'Transferred ₹2,000.00 to DPay Reserve Bank account 1009876543210' },
        },
      },
      BankTransactionsResponse: {
        type: 'object',
        required: ['transactions'],
        properties: {
          transactions: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'integer', example: 1 },
                type: { type: 'string', enum: ['LOAD', 'WITHDRAW', 'SETTLEMENT_CLEARING', 'AUTO_LOAD'], example: 'LOAD' },
                amountPaise: { type: 'integer', example: 500000 },
                status: { type: 'string', enum: ['SUCCESS', 'PENDING', 'FAILED'], example: 'SUCCESS' },
                reference: { type: 'string', example: 'MB-LOAD-7A9B1C2D' },
                description: { type: 'string', nullable: true },
                createdAt: { type: 'integer', example: 1730000000 },
              },
            },
          },
        },
      },
      AdminCreditRequest: {
        type: 'object',
        required: ['amountPaise'],
        properties: {
          amountPaise: { type: 'integer', minimum: 1, maximum: 10000000000, example: 100000 },
          reference: { type: 'string', maxLength: 100, example: 'TOPUP-REF-99' },
        },
      },
      AdminCreditResponse: {
        type: 'object',
        required: ['onlineBalancePaise'],
        properties: {
          onlineBalancePaise: { type: 'integer', example: 100000 },
        },
      },
      AdminFreezeResponse: {
        type: 'object',
        required: ['phone', 'frozen'],
        properties: {
          phone: { type: 'string', example: '9876543210' },
          frozen: { type: 'boolean', example: true },
        },
      },
      AdminFraudEventsResponse: {
        type: 'object',
        required: ['events'],
        properties: {
          events: { type: 'array', items: { type: 'object', additionalProperties: true } },
        },
      },
      HealthLivenessResponse: {
        type: 'object',
        required: ['status', 'service', 'version', 'uptimeSeconds', 'time'],
        properties: {
          status: { type: 'string', example: 'ok' },
          service: { type: 'string', example: 'dpay-backend' },
          version: { type: 'string', example: '0.1.0' },
          uptimeSeconds: { type: 'integer', example: 120 },
          time: { type: 'integer', example: 1730000000 },
        },
      },
      HealthReadinessResponse: {
        type: 'object',
        required: ['status', 'checks', 'time'],
        properties: {
          status: { type: 'string', enum: ['ready', 'unhealthy'], example: 'ready' },
          checks: {
            type: 'object',
            required: ['database', 'redis', 'issuerKey'],
            properties: {
              database: { type: 'string', enum: ['up', 'down'], example: 'up' },
              redis: { type: 'string', enum: ['up', 'down'], example: 'up' },
              issuerKey: { type: 'string', enum: ['loaded', 'missing'], example: 'loaded' },
            },
          },
          time: { type: 'integer', example: 1730000000 },
        },
      },
    },
  },
};

export const openApiYaml = YAML.stringify(openApiSpec);
