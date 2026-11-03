import * as P256 from './p256.ts';
import { SigningDomain } from './p256.ts';
import {
  checkNotExpired,
  NoteCertificate,
  Payment,
  PaymentBody,
  ProtocolConstants,
  ProtocolError,
  RejectReason,
  type TrustAnchors,
  type WalletCertificate,
  WalletLease,
} from './messages.ts';

export interface VerifiedPayment {
  readonly encoded: Buffer;
  readonly body: Buffer;
  readonly paymentId: Buffer;
  readonly payerWalletId: Buffer;
  readonly receiverWalletId: Buffer;
  readonly amount: number;
  readonly totalNoteValue: number;
  readonly challenge: Buffer;
  readonly noteIds: readonly Buffer[];
  readonly noteValues: readonly number[];
  readonly createdAt: number;
  readonly lease: WalletLease;
}

/**
 * Stateless verification of a [Payment] against the receiver's wallet certificate, evaluated at
 * [nowSeconds]. Port of `PaymentVerifier.kt`; the checks and their order must match the client.
 */
export function verifyPayment(
  encoded: Uint8Array,
  receiver: WalletCertificate,
  trust: TrustAnchors,
  nowSeconds: number,
  isWalletBlocked: (walletId: Buffer) => boolean = () => false,
): VerifiedPayment {
  const payment = Payment.decode(encoded);
  const body = PaymentBody.decode(payment.body);

  if (!body.receiverWalletId.equals(receiver.walletId) || !body.receiverKey.equals(receiver.walletKey)) {
    throw new ProtocolError(RejectReason.WRONG_RECEIVER);
  }
  if (body.payerWalletId.equals(receiver.walletId)) {
    throw new ProtocolError(RejectReason.WRONG_RECEIVER, 'self-payment');
  }
  if (isWalletBlocked(body.payerWalletId)) throw new ProtocolError(RejectReason.PAYER_BLOCKED);

  const lease = WalletLease.decodeAndVerify(payment.payerLease, trust);
  if (!lease.walletId.equals(body.payerWalletId)) throw new ProtocolError(RejectReason.LEASE_MISMATCH);
  if (nowSeconds > lease.notAfter + ProtocolConstants.CLOCK_SKEW_SECONDS) {
    throw new ProtocolError(RejectReason.LEASE_EXPIRED);
  }

  const count = body.noteIds.length;
  if (count === 0 || count > ProtocolConstants.MAX_NOTES_PER_PAYMENT || payment.spends.length !== count) {
    throw new ProtocolError(RejectReason.NOTE_MISMATCH);
  }
  if (new Set(body.noteIds.map((id) => id.toString('hex'))).size !== count) {
    throw new ProtocolError(RejectReason.NOTE_MISMATCH, 'duplicate note in payment');
  }

  let total = 0;
  const noteValues: number[] = [];
  payment.spends.forEach((spend, index) => {
    const note = NoteCertificate.decodeAndVerify(spend.noteCertificate, trust);
    if (!note.noteId.equals(body.noteIds[index]!)) {
      throw new ProtocolError(RejectReason.NOTE_MISMATCH, 'note id differs from body');
    }
    if (!note.walletId.equals(body.payerWalletId)) {
      throw new ProtocolError(RejectReason.NOTE_MISMATCH, 'note not owned by payer');
    }
    checkNotExpired(note.notAfter, nowSeconds);
    if (!P256.verify(note.notePublicKey, SigningDomain.NOTE_SPEND, payment.body, spend.signature)) {
      throw new ProtocolError(RejectReason.BAD_NOTE_SIGNATURE);
    }
    total += note.value;
    if (!Number.isSafeInteger(total)) throw new ProtocolError(RejectReason.INVALID_AMOUNT, 'note total overflow');
    noteValues.push(note.value);
  });

  if (body.amount <= 0 || body.amount > total) throw new ProtocolError(RejectReason.INVALID_AMOUNT);

  return {
    encoded: Buffer.from(encoded),
    body: payment.body,
    paymentId: body.paymentId,
    payerWalletId: body.payerWalletId,
    receiverWalletId: body.receiverWalletId,
    amount: body.amount,
    totalNoteValue: total,
    challenge: body.challenge,
    noteIds: body.noteIds,
    noteValues,
    createdAt: body.createdAt,
    lease,
  };
}
