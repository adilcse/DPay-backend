import { randomUUID } from 'node:crypto';
import { BankError, BankException } from '../domain/errors.ts';
import { fullHandle, isValidLocalPart, localPart, RESERVED_HANDLES, suggestHandle } from '../protocol/handles.ts';
import type { Session } from './auth.ts';
import type { ServiceContext } from './context.ts';
import { LedgerKind, postLedger } from './ledger.ts';
import { getOrCreateBankAccount } from './mockBank.ts';

export interface AccountRow {
  id: string;
  phone: string;
  full_name: string;
  handle: string;
  email: string | null;
  online_balance_paise: number;
  bound_device_id: string | null;
  frozen: number;
  created_at: number;
  updated_at: number;
}

export interface Profile {
  phone: string;
  fullName: string;
  /** `name@dpay`; the wallet certificate's displayName. */
  handle: string;
  email: string | null;
}

export const toProfile = (a: AccountRow): Profile => ({ phone: a.phone, fullName: a.full_name, handle: a.handle, email: a.email });

  export async function findAccount(ctx: ServiceContext, session: Session): Promise<AccountRow | undefined> {
    return await ctx.db.get<AccountRow>('SELECT * FROM accounts WHERE phone = ?', session.phone);
  }

    export async function requireAccount(ctx: ServiceContext, session: Session): Promise<AccountRow> {
      const account = await findAccount(ctx, session);
      if (!account) throw new BankException(BankError.ACCOUNT_NOT_REGISTERED, 'complete registration first');
      return account;
    }

      async function handleTaken(ctx: ServiceContext, local: string): Promise<boolean> {
        if (RESERVED_HANDLES.has(local)) return true;
        const res = await ctx.db.get('SELECT 1 AS x FROM accounts WHERE handle = ?', fullHandle(local));
        return !!res;
      }

        export async function isHandleAvailable(ctx: ServiceContext, handle: string): Promise<boolean> {
          const local = localPart(handle);
          return isValidLocalPart(local) && !(await handleTaken(ctx, local));
        }

        /** A free handle based on the user's name: "asha.rao", then "asha.rao1", "asha.rao2", … */
          export async function suggestAvailableHandle(ctx: ServiceContext, fullName: string): Promise<string | null> {
            const base = suggestHandle(fullName);
            if (!isValidLocalPart(base)) return null;
            if (!(await handleTaken(ctx, base))) return fullHandle(base);
            for (let i = 1; i < 100; i++) {
              const candidate = `${base.slice(0, 30 - String(i).length)}${i}`;
              if (isValidLocalPart(candidate) && !(await handleTaken(ctx, candidate))) return fullHandle(candidate);
            }
            return null;
          }

          /** Creates the account for a new user (after OTP) and binds it to this device. */
            export async function register(ctx: ServiceContext, session: Session, fullName: string, handle: string, email: string | null): Promise<Profile> {
              const local = localPart(handle);
              if (!isValidLocalPart(local)) throw new BankException(BankError.INVALID_HANDLE);
              const now = ctx.clock();
                return await ctx.db.transaction(async () => {
                  if (await findAccount(ctx, session)) throw new BankException(BankError.ACCOUNT_EXISTS);
                  if (await handleTaken(ctx, local)) throw new BankException(BankError.HANDLE_TAKEN);
                  const id = randomUUID();
                    await ctx.db.run(
                      `INSERT INTO accounts (id, phone, full_name, handle, email, online_balance_paise, bound_device_id, frozen, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?, ?)`,
                      id,
                      session.phone,
                      fullName,
                      fullHandle(local),
                      email,
                      session.deviceId,
                      now,
                      now,
                    );
                  if (ctx.config.startingBalancePaise > 0) {
                    await postLedger(ctx.db, id, LedgerKind.OPENING_CREDIT, ctx.config.startingBalancePaise, null, now);
                  }
                  // Also provision mock bank account for this user
                  await getOrCreateBankAccount(ctx, id, session.phone, fullHandle(local));

                  const fresh = await ctx.db.get<AccountRow>('SELECT * FROM accounts WHERE id = ?', id);
                  return toProfile(fresh!);
                });
              }

                export async function updateProfile(ctx: ServiceContext, session: Session, fullName: string, email: string | null): Promise<Profile> {
                  const account = await requireAccount(ctx, session);
                  await ctx.db.run('UPDATE accounts SET full_name = ?, email = ?, updated_at = ? WHERE id = ?', fullName, email, ctx.clock(), account.id);
                  return toProfile({ ...account, full_name: fullName, email });
                }

                /**
                 * Binds the account to this device and deregisters the previous one: its wallet is retired (no
                 * more leases, so it stops spending within 5 days) and its sessions are revoked. Notes still on the
                 * old device stay valid for receivers until they expire; unspent ones are refunded after expiry.
                 */
                  export async function moveToThisDevice(ctx: ServiceContext, session: Session): Promise<void> {
                    const now = ctx.clock();
                        await ctx.db.transaction(async () => {
                          const account = await requireAccount(ctx, session);
                          await ctx.db.run(
                            `UPDATE wallets SET status = 'RETIRED', retired_at = ? WHERE account_id = ? AND status = 'ACTIVE'`,
                            now,
                            account.id,
                          );
                          await ctx.db.run('UPDATE accounts SET bound_device_id = ?, updated_at = ? WHERE id = ?', session.deviceId, now, account.id);

                          // Invalidate old sessions in Redis cache
                          const oldSessions = await ctx.db.all<{ token_hash: string }>(
                            'SELECT token_hash FROM sessions WHERE phone = ? AND device_id != ?',
                            account.phone,
                            session.deviceId,
                          );
                          for (const s of oldSessions) {
                            await ctx.redis.deleteSession(s.token_hash);
                          }

                          await ctx.db.run('DELETE FROM sessions WHERE phone = ? AND device_id != ?', account.phone, session.deviceId);
                        });
                    }
