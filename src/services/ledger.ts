import type { Database } from '../db/database.ts';

export const LedgerKind = {
  OPENING_CREDIT: 'OPENING_CREDIT',
  /** Online balance moved into offline notes. */
  OFFLINE_LOAD: 'OFFLINE_LOAD',
  /** An offline payment to this account settled. */
  PAYMENT_RECEIVED: 'PAYMENT_RECEIVED',
  /** Note value above the paid amount, returned to the payer at settlement. */
  PAYMENT_CHANGE_REFUND: 'PAYMENT_CHANGE_REFUND',
  /** Notes that expired unspent (including LOST notes) returned to the owner. */
  NOTE_EXPIRY_REFUND: 'NOTE_EXPIRY_REFUND',
  ADMIN_CREDIT: 'ADMIN_CREDIT',
  /** Money loaded from mock bank account into online balance. */
  BANK_LOAD: 'BANK_LOAD',
  /** Online balance withdrawn / settled to mock bank account. */
  BANK_WITHDRAW: 'BANK_WITHDRAW',
  /** Auto-loaded from mock bank when issuing notes with infinite money. */
  BANK_AUTO_LOAD: 'BANK_AUTO_LOAD',
} as const;
export type LedgerKind = (typeof LedgerKind)[keyof typeof LedgerKind];

/**
 * Moves money in or out of an account's online balance and records it. Must run inside a
 * transaction. Debits never take the balance below zero (also enforced by a CHECK constraint).
 */
  export async function postLedger(
    db: Database,
    accountId: string,
    kind: LedgerKind,
    amountPaise: number,
    reference: string | null,
    now: number,
  ): Promise<number> {
    if (!Number.isSafeInteger(amountPaise) || amountPaise === 0) throw new Error('ledger amount must be a non-zero integer');
    const row = await db.get<{ online_balance_paise: number }>('SELECT online_balance_paise FROM accounts WHERE id = ? FOR UPDATE', accountId);
    if (!row) throw new Error('unknown account');
    const balance = row.online_balance_paise + amountPaise;
    if (balance < 0) throw new Error('ledger would overdraw the account');
    const res = await db.run(
      'UPDATE accounts SET online_balance_paise = ?, updated_at = ? WHERE id = ? AND online_balance_paise + ? >= 0',
      balance,
      now,
      accountId,
      amountPaise,
    );
    if (res.changes !== 1) throw new Error('ledger balance update failed or would overdraw the account');
    await db.run(
      'INSERT INTO ledger_entries (account_id, kind, amount_paise, balance_after_paise, reference, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      accountId,
      kind,
      amountPaise,
      balance,
      reference,
      now,
    );
    return balance;
  }
