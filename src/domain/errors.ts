/**
 * Business error codes. The first block matches `BankError` in the app's `:bank` module
 * (`BankApi.kt`); the rest are server-side additions the network client should map.
 */
export const BankError = {
  INVALID_PHONE: 'INVALID_PHONE',
  INVALID_OTP: 'INVALID_OTP',
  OTP_EXPIRED: 'OTP_EXPIRED',
  OTP_LOCKED: 'OTP_LOCKED',
  RESEND_TOO_SOON: 'RESEND_TOO_SOON',
  NOT_AUTHENTICATED: 'NOT_AUTHENTICATED',
  INVALID_HANDLE: 'INVALID_HANDLE',
  HANDLE_TAKEN: 'HANDLE_TAKEN',
  ACCOUNT_EXISTS: 'ACCOUNT_EXISTS',
  INVALID_CHALLENGE: 'INVALID_CHALLENGE',
  WALLET_NOT_PROVISIONED: 'WALLET_NOT_PROVISIONED',
  INSUFFICIENT_BALANCE: 'INSUFFICIENT_BALANCE',
  LIMIT_EXCEEDED: 'LIMIT_EXCEEDED',
  INVALID_DENOMINATIONS: 'INVALID_DENOMINATIONS',
  WALLET_FROZEN: 'WALLET_FROZEN',
  DEVICE_MOVED: 'DEVICE_MOVED',
  // Server additions
  INVALID_REQUEST: 'INVALID_REQUEST',
  ACCOUNT_NOT_REGISTERED: 'ACCOUNT_NOT_REGISTERED',
  ATTESTATION_FAILED: 'ATTESTATION_FAILED',
  RATE_LIMITED: 'RATE_LIMITED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  INTERNAL: 'INTERNAL',
} as const;
export type BankError = (typeof BankError)[keyof typeof BankError];

export const HTTP_STATUS: Record<BankError, number> = {
  INVALID_PHONE: 400,
  INVALID_OTP: 401,
  OTP_EXPIRED: 410,
  OTP_LOCKED: 423,
  RESEND_TOO_SOON: 429,
  NOT_AUTHENTICATED: 401,
  INVALID_HANDLE: 400,
  HANDLE_TAKEN: 409,
  ACCOUNT_EXISTS: 409,
  INVALID_CHALLENGE: 400,
  WALLET_NOT_PROVISIONED: 409,
  INSUFFICIENT_BALANCE: 422,
  LIMIT_EXCEEDED: 422,
  INVALID_DENOMINATIONS: 400,
  WALLET_FROZEN: 403,
  DEVICE_MOVED: 409,
  INVALID_REQUEST: 400,
  ACCOUNT_NOT_REGISTERED: 404,
  ATTESTATION_FAILED: 422,
  RATE_LIMITED: 429,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  SERVICE_UNAVAILABLE: 503,
  INTERNAL: 500,
};

export class BankException extends Error {
  readonly code: BankError;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: BankError, message: string = code, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.details = details;
  }

  get status(): number {
    return HTTP_STATUS[this.code];
  }
}
