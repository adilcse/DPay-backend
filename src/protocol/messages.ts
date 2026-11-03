import { createHash, type KeyObject } from 'node:crypto';
import * as cbor from './cbor.ts';
import { CborError, type CborMap } from './cbor.ts';
import * as P256 from './p256.ts';
import { InvalidKeyError, SigningDomain } from './p256.ts';

/**
 * DPay protocol v1 messages. Port of `wallet-core/.../protocol/Protocol.kt`; the byte layout
 * and every check must stay identical (see wallet-core/PROTOCOL.md).
 */
export const ProtocolConstants = {
  VERSION: 1,
  ID_SIZE: 16,
  CHALLENGE_SIZE: 16,
  MAX_NOTES_PER_PAYMENT: 16,
  MAX_DISPLAY_NAME_LENGTH: 64,
  /** Tolerated difference between issuer and device clocks when checking expiry. */
  CLOCK_SKEW_SECONDS: 300,
  LEDGER_DIGEST_SIZE: 32,
  TYPE_WALLET_CERTIFICATE: 1,
  TYPE_NOTE_CERTIFICATE: 2,
  TYPE_PAYMENT_REQUEST: 3,
  TYPE_PAYMENT_BODY: 4,
  TYPE_PAYMENT: 5,
  TYPE_WALLET_LEASE: 6,
} as const;

export const RejectReason = {
  MALFORMED: 'MALFORMED',
  UNSUPPORTED_VERSION: 'UNSUPPORTED_VERSION',
  UNKNOWN_ISSUER: 'UNKNOWN_ISSUER',
  BAD_ISSUER_SIGNATURE: 'BAD_ISSUER_SIGNATURE',
  EXPIRED: 'EXPIRED',
  WRONG_RECEIVER: 'WRONG_RECEIVER',
  NOTE_MISMATCH: 'NOTE_MISMATCH',
  BAD_NOTE_SIGNATURE: 'BAD_NOTE_SIGNATURE',
  INVALID_AMOUNT: 'INVALID_AMOUNT',
  PAYER_BLOCKED: 'PAYER_BLOCKED',
  CHALLENGE_UNKNOWN_OR_USED: 'CHALLENGE_UNKNOWN_OR_USED',
  CHALLENGE_EXPIRED: 'CHALLENGE_EXPIRED',
  NOTE_ALREADY_RECEIVED: 'NOTE_ALREADY_RECEIVED',
  LEASE_EXPIRED: 'LEASE_EXPIRED',
  LEASE_MISMATCH: 'LEASE_MISMATCH',
} as const;
export type RejectReason = (typeof RejectReason)[keyof typeof RejectReason];

export class ProtocolError extends Error {
  readonly reason: RejectReason;

  constructor(reason: RejectReason, message: string = reason) {
    super(message);
    this.reason = reason;
  }
}

/** Issuer (bank) public keys by key id. */
export class TrustAnchors {
  private readonly keys: ReadonlyMap<number, KeyObject>;

  constructor(keys: ReadonlyMap<number, KeyObject>) {
    this.keys = keys;
  }

  issuerKey(id: number): KeyObject {
    const key = this.keys.get(id);
    if (!key) throw new ProtocolError(RejectReason.UNKNOWN_ISSUER);
    return key;
  }

  ids(): number[] {
    return [...this.keys.keys()];
  }
}

/** Runs [block], mapping decoding and key errors to MALFORMED. */
function parse<T>(block: () => T): T {
  try {
    return block();
  } catch (e) {
    if (e instanceof CborError || e instanceof InvalidKeyError) {
      throw new ProtocolError(RejectReason.MALFORMED, e.message || 'malformed');
    }
    throw e;
  }
}

function requireHeader(map: CborMap, type: number): void {
  if (map.uint(1) !== ProtocolConstants.VERSION) throw new ProtocolError(RejectReason.UNSUPPORTED_VERSION);
  if (map.uint(2) !== type) throw new ProtocolError(RejectReason.MALFORMED, 'unexpected message type');
}

export function checkNotExpired(notAfter: number, nowSeconds: number): void {
  if (nowSeconds > notAfter + ProtocolConstants.CLOCK_SKEW_SECONDS) throw new ProtocolError(RejectReason.EXPIRED);
}

function requireSize(value: Uint8Array, size: number, what: string): void {
  if (value.length !== size) throw new RangeError(`${what} must be ${size} bytes`);
}

// --- Signed envelope `{1: tbs, 2: raw-signature}` ----------------------------------------------

export const SignedEnvelope = {
  encode(tbs: Uint8Array, signature: Uint8Array): Buffer {
    return cbor.encode(cbor.map([[1, cbor.bytes(tbs)], [2, cbor.bytes(signature)]]));
  },
  decode(encoded: Uint8Array): { tbs: Buffer; signature: Buffer } {
    return parse(() => {
      const map = cbor.asMap(cbor.decode(encoded)).requireExactKeys(1, 2);
      return { tbs: map.bytes(1), signature: map.bytes(2, P256.RAW_SIGNATURE_SIZE) };
    });
  },
};

// --- WalletCertificate -------------------------------------------------------------------------

export interface WalletCertificate {
  readonly encoded: Buffer;
  readonly walletId: Buffer;
  readonly walletKey: Buffer;
  readonly displayName: string;
  readonly notAfter: number;
  readonly issuerKeyId: number;
}

export const WalletCertificate = {
  tbs(walletId: Uint8Array, walletKey: Uint8Array, displayName: string, notAfter: number, issuerKeyId: number): Buffer {
    requireSize(walletId, ProtocolConstants.ID_SIZE, 'walletId');
    requireSize(walletKey, P256.COMPRESSED_KEY_SIZE, 'walletKey');
    if (displayName.length > ProtocolConstants.MAX_DISPLAY_NAME_LENGTH) throw new RangeError('display name too long');
    return cbor.encode(
      cbor.map([
        [1, cbor.uint(ProtocolConstants.VERSION)],
        [2, cbor.uint(ProtocolConstants.TYPE_WALLET_CERTIFICATE)],
        [3, cbor.bytes(walletId)],
        [4, cbor.bytes(walletKey)],
        [5, cbor.text(displayName)],
        [6, cbor.uint(notAfter)],
        [7, cbor.uint(issuerKeyId)],
      ]),
    );
  },

  decodeAndVerify(encoded: Uint8Array, trust: TrustAnchors, nowSeconds: number): WalletCertificate {
    return parse(() => {
      const { tbs, signature } = SignedEnvelope.decode(encoded);
      const map = cbor.asMap(cbor.decode(tbs)).requireExactKeys(1, 2, 3, 4, 5, 6, 7);
      requireHeader(map, ProtocolConstants.TYPE_WALLET_CERTIFICATE);
      const issuerKeyId = map.uint(7);
      if (!P256.verify(trust.issuerKey(issuerKeyId), SigningDomain.WALLET_CERTIFICATE, tbs, signature)) {
        throw new ProtocolError(RejectReason.BAD_ISSUER_SIGNATURE);
      }
      const displayName = map.text(5);
      if (displayName.length > ProtocolConstants.MAX_DISPLAY_NAME_LENGTH) throw new CborError('display name too long');
      const cert: WalletCertificate = {
        encoded: Buffer.from(encoded),
        walletId: map.bytes(3, ProtocolConstants.ID_SIZE),
        walletKey: map.bytes(4, P256.COMPRESSED_KEY_SIZE),
        displayName,
        notAfter: map.uint(6),
        issuerKeyId,
      };
      P256.decompress(cert.walletKey); // validates the point
      checkNotExpired(cert.notAfter, nowSeconds);
      return cert;
    });
  },
};

// --- NoteCertificate ---------------------------------------------------------------------------

export interface NoteCertificate {
  readonly encoded: Buffer;
  readonly noteId: Buffer;
  readonly walletId: Buffer;
  readonly value: number;
  readonly noteKey: Buffer;
  readonly notAfter: number;
  readonly issuerKeyId: number;
}

export const NoteCertificate = {
  tbs(noteId: Uint8Array, walletId: Uint8Array, value: number, noteKey: Uint8Array, notAfter: number, issuerKeyId: number): Buffer {
    requireSize(noteId, ProtocolConstants.ID_SIZE, 'noteId');
    requireSize(walletId, ProtocolConstants.ID_SIZE, 'walletId');
    if (!(value > 0)) throw new RangeError('note value must be positive');
    requireSize(noteKey, P256.COMPRESSED_KEY_SIZE, 'noteKey');
    return cbor.encode(
      cbor.map([
        [1, cbor.uint(ProtocolConstants.VERSION)],
        [2, cbor.uint(ProtocolConstants.TYPE_NOTE_CERTIFICATE)],
        [3, cbor.bytes(noteId)],
        [4, cbor.bytes(walletId)],
        [5, cbor.uint(value)],
        [6, cbor.bytes(noteKey)],
        [7, cbor.uint(notAfter)],
        [8, cbor.uint(issuerKeyId)],
      ]),
    );
  },

  /** Verifies the issuer signature. Expiry is checked separately. */
  decodeAndVerify(encoded: Uint8Array, trust: TrustAnchors): NoteCertificate & { notePublicKey: KeyObject } {
    return parse(() => {
      const { tbs, signature } = SignedEnvelope.decode(encoded);
      const map = cbor.asMap(cbor.decode(tbs)).requireExactKeys(1, 2, 3, 4, 5, 6, 7, 8);
      requireHeader(map, ProtocolConstants.TYPE_NOTE_CERTIFICATE);
      const issuerKeyId = map.uint(8);
      if (!P256.verify(trust.issuerKey(issuerKeyId), SigningDomain.NOTE_CERTIFICATE, tbs, signature)) {
        throw new ProtocolError(RejectReason.BAD_ISSUER_SIGNATURE);
      }
      const noteKey = map.bytes(6, P256.COMPRESSED_KEY_SIZE);
      const cert = {
        encoded: Buffer.from(encoded),
        noteId: map.bytes(3, ProtocolConstants.ID_SIZE),
        walletId: map.bytes(4, ProtocolConstants.ID_SIZE),
        value: map.uint(5),
        noteKey,
        notAfter: map.uint(7),
        issuerKeyId,
        notePublicKey: P256.decompress(noteKey),
      };
      if (cert.value <= 0) throw new ProtocolError(RejectReason.MALFORMED, 'zero-value note');
      return cert;
    });
  },
};

// --- WalletLease -------------------------------------------------------------------------------

export interface WalletLease {
  readonly encoded: Buffer;
  readonly walletId: Buffer;
  readonly walletKey: Buffer;
  readonly sequence: number;
  readonly issuedAt: number;
  readonly notAfter: number;
  readonly outstandingValue: number;
  readonly ledgerDigest: Buffer;
  readonly issuerKeyId: number;
}

const LEDGER_DIGEST_TAG = 'DPAY/v1/ledger';

export const WalletLease = {
  tbs(
    walletId: Uint8Array,
    walletKey: Uint8Array,
    sequence: number,
    issuedAt: number,
    notAfter: number,
    outstandingValue: number,
    ledgerDigest: Uint8Array,
    issuerKeyId: number,
  ): Buffer {
    requireSize(walletId, ProtocolConstants.ID_SIZE, 'walletId');
    requireSize(walletKey, P256.COMPRESSED_KEY_SIZE, 'walletKey');
    requireSize(ledgerDigest, ProtocolConstants.LEDGER_DIGEST_SIZE, 'ledgerDigest');
    if (!(notAfter > issuedAt)) throw new RangeError('empty lease period');
    return cbor.encode(
      cbor.map([
        [1, cbor.uint(ProtocolConstants.VERSION)],
        [2, cbor.uint(ProtocolConstants.TYPE_WALLET_LEASE)],
        [3, cbor.bytes(walletId)],
        [4, cbor.bytes(walletKey)],
        [5, cbor.uint(sequence)],
        [6, cbor.uint(issuedAt)],
        [7, cbor.uint(notAfter)],
        [8, cbor.uint(outstandingValue)],
        [9, cbor.bytes(ledgerDigest)],
        [10, cbor.uint(issuerKeyId)],
      ]),
    );
  },

  /** SHA-256("DPAY/v1/ledger" ‖ 0x00 ‖ note ids in ascending unsigned byte order). */
  ledgerDigest(noteIds: readonly Uint8Array[]): Buffer {
    const digest = createHash('sha256');
    digest.update(LEDGER_DIGEST_TAG, 'utf8');
    digest.update(Buffer.from([0]));
    for (const id of [...noteIds].sort((a, b) => Buffer.compare(a, b))) digest.update(id);
    return digest.digest();
  },

  /** Verifies the bank signature and structure. Time and ownership checks are up to the caller. */
  decodeAndVerify(encoded: Uint8Array, trust: TrustAnchors): WalletLease {
    return parse(() => {
      const { tbs, signature } = SignedEnvelope.decode(encoded);
      const map = cbor.asMap(cbor.decode(tbs)).requireExactKeys(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
      requireHeader(map, ProtocolConstants.TYPE_WALLET_LEASE);
      const issuerKeyId = map.uint(10);
      if (!P256.verify(trust.issuerKey(issuerKeyId), SigningDomain.WALLET_LEASE, tbs, signature)) {
        throw new ProtocolError(RejectReason.BAD_ISSUER_SIGNATURE);
      }
      const lease: WalletLease = {
        encoded: Buffer.from(encoded),
        walletId: map.bytes(3, ProtocolConstants.ID_SIZE),
        walletKey: map.bytes(4, P256.COMPRESSED_KEY_SIZE),
        sequence: map.uint(5),
        issuedAt: map.uint(6),
        notAfter: map.uint(7),
        outstandingValue: map.uint(8),
        ledgerDigest: map.bytes(9, ProtocolConstants.LEDGER_DIGEST_SIZE),
        issuerKeyId,
      };
      if (lease.notAfter <= lease.issuedAt) throw new ProtocolError(RejectReason.MALFORMED, 'empty lease period');
      return lease;
    });
  },
};

// --- PaymentRequest (receiver → payer) ---------------------------------------------------------

export const PaymentRequest = {
  encode(receiverCertificate: Uint8Array, challenge: Uint8Array, requestedAmount: number): Buffer {
    return cbor.encode(
      cbor.map([
        [1, cbor.uint(ProtocolConstants.VERSION)],
        [2, cbor.uint(ProtocolConstants.TYPE_PAYMENT_REQUEST)],
        [3, cbor.bytes(receiverCertificate)],
        [4, cbor.bytes(challenge)],
        [5, cbor.uint(requestedAmount)],
      ]),
    );
  },
};

// --- PaymentBody & Payment (payer → receiver) --------------------------------------------------

export interface PaymentBody {
  readonly paymentId: Buffer;
  readonly payerWalletId: Buffer;
  readonly receiverWalletId: Buffer;
  readonly receiverKey: Buffer;
  readonly challenge: Buffer;
  /** Amount credited to the receiver. Excess note value is refunded to the payer at settlement. */
  readonly amount: number;
  /** Payer's local clock, epoch seconds. Display only, never trusted. */
  readonly createdAt: number;
  readonly noteIds: readonly Buffer[];
}

export const PaymentBody = {
  encode(body: PaymentBody): Buffer {
    return cbor.encode(
      cbor.map([
        [1, cbor.uint(ProtocolConstants.VERSION)],
        [2, cbor.uint(ProtocolConstants.TYPE_PAYMENT_BODY)],
        [3, cbor.bytes(body.paymentId)],
        [4, cbor.bytes(body.payerWalletId)],
        [5, cbor.bytes(body.receiverWalletId)],
        [6, cbor.bytes(body.receiverKey)],
        [7, cbor.bytes(body.challenge)],
        [8, cbor.uint(body.amount)],
        [9, cbor.uint(body.createdAt)],
        [10, cbor.array(body.noteIds.map((id) => cbor.bytes(id)))],
      ]),
    );
  },

  decode(encoded: Uint8Array): PaymentBody {
    return parse(() => {
      const map = cbor.asMap(cbor.decode(encoded)).requireExactKeys(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
      requireHeader(map, ProtocolConstants.TYPE_PAYMENT_BODY);
      return {
        paymentId: map.bytes(3, ProtocolConstants.ID_SIZE),
        payerWalletId: map.bytes(4, ProtocolConstants.ID_SIZE),
        receiverWalletId: map.bytes(5, ProtocolConstants.ID_SIZE),
        receiverKey: map.bytes(6, P256.COMPRESSED_KEY_SIZE),
        challenge: map.bytes(7, ProtocolConstants.CHALLENGE_SIZE),
        amount: map.uint(8),
        createdAt: map.uint(9),
        noteIds: map.array(10).map((id) => {
          const b = cbor.asBytes(id);
          if (b.length !== ProtocolConstants.ID_SIZE) throw new CborError('bad note id');
          return b;
        }),
      };
    });
  },
};

export interface NoteSpend {
  readonly noteCertificate: Buffer;
  readonly signature: Buffer;
}

export interface Payment {
  readonly body: Buffer;
  readonly spends: readonly NoteSpend[];
  readonly payerLease: Buffer;
}

export const Payment = {
  encode(payment: Payment): Buffer {
    return cbor.encode(
      cbor.map([
        [1, cbor.uint(ProtocolConstants.VERSION)],
        [2, cbor.uint(ProtocolConstants.TYPE_PAYMENT)],
        [3, cbor.bytes(payment.body)],
        [4, cbor.array(payment.spends.map((s) => cbor.map([[1, cbor.bytes(s.noteCertificate)], [2, cbor.bytes(s.signature)]])))],
        [5, cbor.bytes(payment.payerLease)],
      ]),
    );
  },

  decode(encoded: Uint8Array): Payment {
    return parse(() => {
      const map = cbor.asMap(cbor.decode(encoded)).requireExactKeys(1, 2, 3, 4, 5);
      requireHeader(map, ProtocolConstants.TYPE_PAYMENT);
      return {
        body: map.bytes(3),
        spends: map.array(4).map((item) => {
          const spend = cbor.asMap(item).requireExactKeys(1, 2);
          return { noteCertificate: spend.bytes(1), signature: spend.bytes(2, P256.RAW_SIGNATURE_SIZE) };
        }),
        payerLease: map.bytes(5),
      };
    });
  },
};
