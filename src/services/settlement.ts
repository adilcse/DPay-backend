import { createHash } from 'node:crypto';
import { Limits } from '../domain/limits.ts';
import { Payment, PaymentBody, ProtocolError, WalletCertificate, WalletLease } from '../protocol/messages.ts';
import { verifyPayment, type VerifiedPayment } from '../protocol/verifier.ts';
import { requireAccount } from './accounts.ts';
import type { Session } from './auth.ts';
import { hex, type ServiceContext } from './context.ts';
import { LedgerKind, postLedger } from './ledger.ts';
import { refundExpiredNotes, type NoteRow, type WalletRow } from './wallets.ts';

export interface SettlementUpload {
  /** Received payments: encoded bytes and the receive time (epoch seconds, receiver's clock). */
  readonly received: ReadonlyArray<{ payment: Buffer; receivedAt: number }>;
  /** Fully signed outgoing payments (encoded bytes). */
  readonly sent: readonly Buffer[];
}

export const SettlementRejection = {
  /** Undecodable or fails PaymentVerifier (reason has the RejectReason). */
  INVALID_PAYMENT: 'INVALID_PAYMENT',
  /** The uploader is not the receiver (for `received`) or payer (for `sent`). */
  NOT_YOUR_PAYMENT: 'NOT_YOUR_PAYMENT',
  UNKNOWN_WALLET: 'UNKNOWN_WALLET',
  /** A note in it was never issued by this bank. */
  UNKNOWN_NOTE: 'UNKNOWN_NOTE',
  /** A note in it was already refunded (uploaded after expiry + grace). */
  NOTE_REFUNDED: 'NOTE_REFUNDED',
  /** A note in it was already spent in a different payment: hardware compromise. */
  DOUBLE_SPEND: 'DOUBLE_SPEND',
  /** Same payment id, different body. */
  PAYMENT_ID_CONFLICT: 'PAYMENT_ID_CONFLICT',
  /** receivedAt is in the future or before the payer's lease was issued. */
  BAD_RECEIVE_TIME: 'BAD_RECEIVE_TIME',
} as const;
export type SettlementRejection = (typeof SettlementRejection)[keyof typeof SettlementRejection];

export interface Rejection {
  direction: 'received' | 'sent';
  index: number;
  paymentId: Buffer | null;
  code: SettlementRejection;
  reason?: string;
}

export interface SettlementReport {
  /** Payment ids credited to this account (received), including ones settled earlier. */
  settledReceived: Buffer[];
  /** Payment ids debited from this account's notes (sent), including ones settled earlier. */
  settledSent: Buffer[];
  /** Received payments the bank refused (invalid or a duplicate spend). */
  rejectedReceived: Buffer[];
  /** Sent payments the bank refused. */
  rejectedSent: Buffer[];
  rejections: Rejection[];
  creditedPaise: number;
  refundedPaise: number;
  onlineBalancePaise: number;
}

interface PaymentRow {
  payment_id: string;
  body_hash: string;
  payer_account_id: string;
  receiver_account_id: string;
}

type Outcome =
  | { ok: true; paymentId: Buffer; creditedToUploader: number; refundedToUploader: number }
  | { ok: false; paymentId: Buffer | null; code: SettlementRejection; reason?: string };

const reject = (paymentId: Buffer | null, code: SettlementRejection, reason?: string): Outcome => ({
  ok: false,
  paymentId,
  code,
  ...(reason ? { reason } : {}),
});

/**
 * Settles uploaded offline payments (PROTOCOL.md "Settlement"). One central ledger, so whichever
 * side uploads first settles the payment for both: the receiver is credited `amount`, and the
 * payer gets `Σ note values − amount` back. Each payment is its own transaction, and re-uploads
 * are idempotent.
 */
  export async function settle(ctx: ServiceContext, session: Session, upload: SettlementUpload): Promise<SettlementReport> {
    const account = await requireAccount(ctx, session);
    const now = ctx.clock();
    const report: SettlementReport = {
      settledReceived: [],
      settledSent: [],
      rejectedReceived: [],
      rejectedSent: [],
      rejections: [],
      creditedPaise: 0,
      refundedPaise: 0,
      onlineBalancePaise: 0,
    };

    const handle = (direction: 'received' | 'sent', index: number, outcome: Outcome) => {
      if (outcome.ok) {
        (direction === 'received' ? report.settledReceived : report.settledSent).push(outcome.paymentId);
        report.creditedPaise += outcome.creditedToUploader;
        report.refundedPaise += outcome.refundedToUploader;
      } else {
        if (outcome.paymentId) (direction === 'received' ? report.rejectedReceived : report.rejectedSent).push(outcome.paymentId);
        report.rejections.push({
          direction,
          index,
          paymentId: outcome.paymentId,
          code: outcome.code,
          ...(outcome.reason ? { reason: outcome.reason } : {}),
        });
      }
    };

      const receivedItems = upload.received.slice(0, Limits.MAX_SETTLEMENT_ITEMS);
      for (let i = 0; i < receivedItems.length; i++) {
        const item = receivedItems[i]!;
        const outcome = await settleOne(ctx, account.id, item.payment, 'RECEIVER', item.receivedAt, now);
        handle('received', i, outcome);
      }

      const sentItems = upload.sent.slice(0, Limits.MAX_SETTLEMENT_ITEMS);
      for (let i = 0; i < sentItems.length; i++) {
        const encoded = sentItems[i]!;
        const outcome = await settleOne(ctx, account.id, encoded, 'PAYER', null, now);
        handle('sent', i, outcome);
      }

      await ctx.db.transaction(async () => {
        report.refundedPaise += await refundExpiredNotes(ctx, now, account.id);
      });

      const balanceRow = await ctx.db.get<{ b: number }>('SELECT online_balance_paise AS b FROM accounts WHERE id = ?', account.id);
      report.onlineBalancePaise = balanceRow!.b;
      ctx.logger.info('settlement', {
        received: upload.received.length,
        sent: upload.sent.length,
        settled: report.settledReceived.length + report.settledSent.length,
        rejected: report.rejections.length,
      });
      return report;
    }

      async function settleOne(
        ctx: ServiceContext,
        uploaderAccountId: string,
        encoded: Buffer,
        uploadedBy: 'PAYER' | 'RECEIVER',
        receivedAt: number | null,
        now: number,
): Promise < Outcome > {
      // Decode enough to identify the payment.
      let body: PaymentBody;
      let lease: WalletLease;
      let payment: Payment;
      try {
        payment = Payment.decode(encoded);
        body = PaymentBody.decode(payment.body);
      } catch(e) {
        return reject(null, SettlementRejection.INVALID_PAYMENT, e instanceof ProtocolError ? e.reason : 'MALFORMED');
      }
  const paymentId = body.paymentId;
      const bodyHash = createHash('sha256').update(payment.body).digest('hex');

      const receiverWallet = await ctx.db.get<WalletRow>('SELECT * FROM wallets WHERE wallet_id = ?', hex(body.receiverWalletId));
      const payerWallet = await ctx.db.get<WalletRow>('SELECT * FROM wallets WHERE wallet_id = ?', hex(body.payerWalletId));
      if(!receiverWallet || !payerWallet) return reject(paymentId, SettlementRejection.UNKNOWN_WALLET);
    const uploaderWallet = uploadedBy === 'RECEIVER' ? receiverWallet : payerWallet;
    if (uploaderWallet.account_id !== uploaderAccountId) return reject(paymentId, SettlementRejection.NOT_YOUR_PAYMENT);

    // Already settled (by either side)? Re-uploads are idempotent.
    const existing = await ctx.db.get<PaymentRow>('SELECT * FROM payments WHERE payment_id = ?', hex(paymentId));
    if (existing && existing.body_hash === bodyHash) {
      return { ok: true, paymentId, creditedToUploader: 0, refundedToUploader: 0 };
    }

    try {
      lease = WalletLease.decodeAndVerify(payment.payerLease, ctx.issuer.trustAnchors);
    } catch (e) {
      return reject(paymentId, SettlementRejection.INVALID_PAYMENT, e instanceof ProtocolError ? e.reason : 'MALFORMED');
    }

    // When the payment changed hands. The receiver reports it; for a payer upload, use the payer's
    // (untrusted) createdAt clamped into the lease window, since the lease is what gated the spend.
    let evaluatedAt: number;
    if (receivedAt !== null) {
      if (receivedAt > now + Limits.CLOCK_SKEW_SECONDS || receivedAt < lease.issuedAt - Limits.CLOCK_SKEW_SECONDS) {
        return reject(paymentId, SettlementRejection.BAD_RECEIVE_TIME);
      }
      evaluatedAt = receivedAt;
    } else {
      evaluatedAt = Math.max(lease.issuedAt, Math.min(body.createdAt, lease.notAfter, now));
    }

    let verified: VerifiedPayment;
    try {
      const receiverCert = WalletCertificate.decodeAndVerify(Buffer.from(receiverWallet.certificate), ctx.issuer.trustAnchors, evaluatedAt);
      verified = verifyPayment(encoded, receiverCert, ctx.issuer.trustAnchors, evaluatedAt);
    } catch (e) {
      if (e instanceof ProtocolError) return reject(paymentId, SettlementRejection.INVALID_PAYMENT, e.reason);
      throw e;
    }
    // The lease must be one this bank issued to this wallet key.
    if (!lease.walletKey.equals(Buffer.from(payerWallet.wallet_key, 'hex')) || lease.sequence > payerWallet.lease_sequence) {
      return reject(paymentId, SettlementRejection.INVALID_PAYMENT, 'LEASE_MISMATCH');
    }

      return await ctx.db.transaction(async (): Promise<Outcome> => {
        // Re-check inside the transaction (concurrent upload by the other side).
        const again = await ctx.db.get<PaymentRow>('SELECT * FROM payments WHERE payment_id = ?', hex(paymentId));
        if (again && again.body_hash === bodyHash) return { ok: true, paymentId, creditedToUploader: 0, refundedToUploader: 0 };

        const notes: NoteRow[] = [];
        const conflicts: NoteRow[] = [];
        for (let i = 0; i < verified.noteIds.length; i++) {
          const note = await ctx.db.get<NoteRow>('SELECT * FROM notes WHERE note_id = ?', hex(verified.noteIds[i]!));
          if (!note || note.wallet_id !== payerWallet.wallet_id || note.value_paise !== verified.noteValues[i]) {
            // Valid issuer signature on a note we have no record of: the issuer key or our DB is compromised.
            await recordFraud(ctx, 'UNKNOWN_NOTE', payerWallet.wallet_id, hex(verified.noteIds[i]!), null, hex(paymentId), now);
            return reject(paymentId, SettlementRejection.UNKNOWN_NOTE);
          }
          if (note.status === 'REFUNDED') return reject(paymentId, SettlementRejection.NOTE_REFUNDED);
          if (note.status === 'SPENT') conflicts.push(note);
          notes.push(note);
        }

        if (conflicts.length > 0) {
          // A second, different valid spend of the same note: cryptographic proof the payer's secure
          // hardware was compromised. Freeze the wallet and account, block the wallet for receivers.
          for (const c of conflicts) {
            await recordFraud(ctx, 'DOUBLE_SPEND', payerWallet.wallet_id, c.note_id, c.payment_id, hex(paymentId), now);
          }
            await ctx.db.run('UPDATE wallets SET frozen = 1 WHERE wallet_id = ?', payerWallet.wallet_id);
          await ctx.db.run('UPDATE accounts SET frozen = 1, updated_at = ? WHERE id = ?', now, payerWallet.account_id);
          await ctx.db.run(
            'INSERT OR IGNORE INTO blocked_wallets (wallet_id, reason, created_at) VALUES (?, ?, ?)',
            payerWallet.wallet_id,
            'DOUBLE_SPEND',
            now,
          );
          // Fast cache in Redis
          await ctx.redis.addToBlocklist(payerWallet.wallet_id);

          ctx.logger.error('double spend detected', { payerWalletId: payerWallet.wallet_id, paymentId: hex(paymentId) });
          if (!ctx.config.guaranteeOfflinePayments || again) {
            return reject(paymentId, SettlementRejection.DOUBLE_SPEND);
          }
        } else if (again) {
          return reject(paymentId, SettlementRejection.PAYMENT_ID_CONFLICT);
        }

        // Settle: close the notes, credit the receiver, refund change to the payer.
        const guaranteed = conflicts.length > 0;
        for (const note of notes) {
          if (note.status === 'OUTSTANDING') {
            await ctx.db.run(`UPDATE notes SET status = 'SPENT', payment_id = ?, closed_at = ? WHERE note_id = ?`, hex(paymentId), now, note.note_id);
          }
        }
        // A guaranteed double spend refunds no change to the (frozen) payer.
        const change = guaranteed ? 0 : verified.totalNoteValue - verified.amount;
          await ctx.db.run(
            `INSERT INTO payments (payment_id, body_hash, payer_wallet_id, receiver_wallet_id, payer_account_id, receiver_account_id,
         amount_paise, total_note_value_paise, change_paise, note_count, created_at_claimed, received_at, settled_at, uploaded_by,
         double_spend_guaranteed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            hex(paymentId),
            bodyHash,
            payerWallet.wallet_id,
            receiverWallet.wallet_id,
            payerWallet.account_id,
            receiverWallet.account_id,
            verified.amount,
            verified.totalNoteValue,
            change,
            verified.noteIds.length,
            verified.createdAt,
            receivedAt,
            now,
            uploadedBy,
            guaranteed ? 1 : 0,
          );
        await postLedger(ctx.db, receiverWallet.account_id, LedgerKind.PAYMENT_RECEIVED, verified.amount, `payment:${hex(paymentId)}`, now);
        if (change > 0) {
          await postLedger(ctx.db, payerWallet.account_id, LedgerKind.PAYMENT_CHANGE_REFUND, change, `payment:${hex(paymentId)}`, now);
        }

        return {
          ok: true,
          paymentId,
          creditedToUploader: receiverWallet.account_id === uploaderAccountId ? verified.amount : 0,
          refundedToUploader: payerWallet.account_id === uploaderAccountId ? change : 0,
        };
      });
    }

      async function recordFraud(
        ctx: ServiceContext,
        kind: 'DOUBLE_SPEND' | 'UNKNOWN_NOTE',
        walletId: string,
        noteId: string,
        firstPaymentId: string | null,
        secondPaymentId: string,
        now: number,
      ): Promise < void> {
        await ctx.db.run(
          `INSERT INTO fraud_events (kind, wallet_id, note_id, first_payment_id, second_payment_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
          kind,
          walletId,
          noteId,
          firstPaymentId,
          secondPaymentId,
          now,
        );
      }

      /** Settlement status of one payment, for the payer or receiver. */
          export async function paymentStatus(ctx: ServiceContext, session: Session, paymentId: Buffer) {
            const account = await requireAccount(ctx, session);
        const row = await ctx.db.get<{
          payment_id: string;
          payer_account_id: string;
          receiver_account_id: string;
          amount_paise: number;
          total_note_value_paise: number;
          change_paise: number;
          note_count: number;
          created_at_claimed: number;
          received_at: number | null;
          settled_at: number;
        }>('SELECT * FROM payments WHERE payment_id = ?', hex(paymentId));
        if (!row || (row.payer_account_id !== account.id && row.receiver_account_id !== account.id)) return null;
        const counterpartyId = row.payer_account_id === account.id ? row.receiver_account_id : row.payer_account_id;
        const counterparty = await ctx.db.get<{ handle: string }>('SELECT handle FROM accounts WHERE id = ?', counterpartyId);
        return {
          paymentId,
          direction: row.payer_account_id === account.id ? ('SENT' as const) : ('RECEIVED' as const),
          status: 'SETTLED' as const,
          amountPaise: row.amount_paise,
          totalNoteValuePaise: row.total_note_value_paise,
          changeRefundedPaise: row.change_paise,
          noteCount: row.note_count,
          counterpartyHandle: counterparty?.handle ?? null,
          createdAt: row.created_at_claimed,
          receivedAt: row.received_at,
          settledAt: row.settled_at,
        };
      }
