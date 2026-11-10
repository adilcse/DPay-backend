/** Product limits shared with the client (`OfflineLimits.kt`, `FakeBank.kt`). */
export const Limits = {
  /** ₹5,000: maximum unexpired, unsettled note value per wallet. */
  MAX_OFFLINE_BALANCE_PAISE: 5_000_00,
  /** Wallet leases last exactly 5 days; the client rejects anything longer. */
  LEASE_VALIDITY_SECONDS: 5 * 86_400,
  OTP_TTL_SECONDS: 5 * 60,
  OTP_RESEND_SECONDS: 30,
  OTP_MAX_ATTEMPTS: 5,
  /** OTP sends per phone per hour. */
  OTP_MAX_SENDS_PER_HOUR: 5,
  /** Wrong codes per phone per hour, counted across codes (a resend does not reset it). */
  OTP_MAX_FAILURES_PER_HOUR: 10,
  /** Concurrent sessions per phone; the oldest are dropped when a new login exceeds this. */
  MAX_SESSIONS_PER_PHONE: 5,
  /** Moving the account to a new device needs a session that was created (OTP verified) this recently. */
  DEVICE_MOVE_MAX_SESSION_AGE_SECONDS: 15 * 60,
  /** Sessions are cached in Redis for at most this long before PostgreSQL is consulted again. */
  SESSION_CACHE_TTL_SECONDS: 5 * 60,
  CHALLENGE_TTL_SECONDS: 10 * 60,
  WALLET_CERT_LIFETIME_SECONDS: 365 * 86_400,
  CLOCK_SKEW_SECONDS: 300,
  MAX_NOTES_PER_LOAD: 100,
  MAX_SETTLEMENT_ITEMS: 200,
} as const;

/** Indian mobile number without +91: ten digits starting 6–9 (same rule as FakeBank). */
export const PHONE_PATTERN = /^[6-9][0-9]{9}$/;
