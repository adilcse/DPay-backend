import { BankError, BankException } from '../domain/errors.ts';
import { maskPhone } from '../lib/logger.ts';
import { revokeSessions, type AccountRow } from './accounts.ts';
import type { ServiceContext } from './context.ts';
import { LedgerKind, postLedger } from './ledger.ts';

  async function accountByPhone(ctx: ServiceContext, phone: string): Promise<AccountRow> {
    const account = await ctx.db.get<AccountRow>('SELECT * FROM accounts WHERE phone = ?', phone);
    if (!account) throw new BankException(BankError.NOT_FOUND, 'no such account');
    return account;
  }

  /** Back-office top-up of an account's online balance (stands in for a bank transfer / UPI collect). */
    export async function creditAccount(ctx: ServiceContext, phone: string, amountPaise: number, reference: string | null) {
      const now = ctx.clock();
        return await ctx.db.transaction(async () => {
          const account = await accountByPhone(ctx, phone);
          const balance = await postLedger(ctx.db, account.id, LedgerKind.ADMIN_CREDIT, amountPaise, reference, now);
          ctx.logger.info('admin action', { action: 'credit', phone: maskPhone(phone), amountPaise, reference });
          return { onlineBalancePaise: balance };
        });
      }

/**
 * Frozen accounts are refused by every money-moving route and get no new notes or leases, so their
 * offline spending stops within 5 days. Freezing also signs the account out everywhere.
 */
        export async function setAccountFrozen(ctx: ServiceContext, phone: string, frozen: boolean) {
          const account = await accountByPhone(ctx, phone);
          await ctx.db.run('UPDATE accounts SET frozen = ?, updated_at = ? WHERE id = ?', frozen ? 1 : 0, ctx.clock(), account.id);
          const sessionsRevoked = frozen ? (await revokeSessions(ctx, account.phone)).length : 0;
          ctx.logger.info('admin action', { action: frozen ? 'freeze' : 'unfreeze', phone: maskPhone(phone), sessionsRevoked });
          return { phone, frozen };
        }

          export async function fraudEvents(ctx: ServiceContext, limit: number) {
            return await ctx.db.all<Record<string, unknown>>('SELECT * FROM fraud_events ORDER BY id DESC LIMIT ?', limit);
          }
