import { requireAccount } from './accounts.ts';
import type { Session } from './auth.ts';
import type { ServiceContext } from './context.ts';
import { refundExpiredNotes } from './wallets.ts';

/** Online balance (after refunding any notes past expiry + grace). */
  export async function accountSummary(ctx: ServiceContext, session: Session) {
    const account = await requireAccount(ctx, session);
    const now = ctx.clock();
  return await ctx.db.transaction(async () => {
        await refundExpiredNotes(ctx, now, account.id);
        const row = await ctx.db.get<{ b: number }>('SELECT online_balance_paise AS b FROM accounts WHERE id = ?', account.id);
        const offline = await ctx.db.get<{ v: number | null }>(
          `SELECT SUM(value_paise) AS v FROM notes WHERE account_id = ? AND status = 'OUTSTANDING'`,
          account.id,
    );
      return { onlineBalancePaise: Number(row!.b), offlineOutstandingPaise: Number(offline?.v ?? 0) };
    });
  }

  /** Online ledger history, newest first (cursor = last entry id seen). */
      export async function transactions(ctx: ServiceContext, session: Session, limit: number, before: number | undefined) {
        const account = await requireAccount(ctx, session);
    const rows = await ctx.db.all<{
      id: number;
      kind: string;
      amount_paise: number;
      balance_after_paise: number;
      reference: string | null;
      created_at: number;
    }>(
      `SELECT id, kind, amount_paise, balance_after_paise, reference, created_at FROM ledger_entries
     WHERE account_id = ? AND id < ? ORDER BY id DESC LIMIT ?`,
      account.id,
      before ?? Number.MAX_SAFE_INTEGER,
      limit,
    );
    return {
      entries: rows.map((r) => {
        const [refKind, refId] = (r.reference ?? '').split(':');
        return {
          id: r.id,
          kind: r.kind,
          amountPaise: r.amount_paise,
          balanceAfterPaise: r.balance_after_paise,
          paymentId: refKind === 'payment' && refId ? Buffer.from(refId, 'hex') : null,
          noteId: refKind === 'note' && refId ? Buffer.from(refId, 'hex') : null,
          createdAt: r.created_at,
        };
      }),
      nextCursor: rows.length === limit ? rows[rows.length - 1]!.id : null,
    };
  }

  /** Wallet ids receivers should refuse offline (`isWalletBlocked`): proven double spenders. */
    export async function blocklist(ctx: ServiceContext) {
      const rows = await ctx.db.all<{ wallet_id: string; created_at: number }>('SELECT wallet_id, created_at FROM blocked_wallets ORDER BY created_at');
      return {
        walletIds: rows.map((r) => Buffer.from(r.wallet_id, 'hex')),
        updatedAt: rows.length ? rows[rows.length - 1]!.created_at : 0,
      };
    }
