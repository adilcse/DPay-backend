/**
 * CENTRAL BANK CLEARING & LIQUIDITY SIMULATOR (RBI Interbank Clearing Gateway)
 *
 * NOTE: Per architecture requirements, this is the ONLY simulated/faked component in the DPay backend.
 * In a sovereign banking deployment, this service connects directly to Reserve Bank of India (RBI)
 * or NPCI clearing rails (RTGS / NEFT / IMPS / UPI e-Mandates).
 *
 * Here, it simulates infinite central bank fiat liquidity:
 * 1. Infinite money wallet loading (`/v1/bank/load` or `/v1/central-bank/load`).
 * 2. Automatic overdraft/liquidity coverage on offline note issuance (`autoFundShortfall`).
 * 3. Clearing and settlement sweep payouts (`withdrawToBank`).
 * 4. Interbank transaction ledgering (`mock_bank_transactions`).
 *
 * All other backend systems (P-256 Attestation, 5-day leases, Canonical CBOR note issuing,
 * atomic double-spend detection, double-entry ledgers, and Redis session fast-path) are 100% production-ready.
 */

import { randomUUID } from 'node:crypto';
import { BankError, BankException } from '../domain/errors.ts';
import { requireAccount } from './accounts.ts';
import type { Session } from './auth.ts';
import type { ServiceContext } from './context.ts';
import { LedgerKind, postLedger } from './ledger.ts';

export interface MockBankAccountRow {
  id: string;
  account_id: string;
  account_number: string;
  ifsc: string;
  bank_name: string;
  upi_vpa: string;
  infinite_money: number;
  balance_paise: number;
  status: string;
  created_at: number;
  updated_at: number;
}

export interface MockBankTransactionRow {
  id: number;
  account_id: string;
  bank_account_id: string;
  type: 'LOAD' | 'WITHDRAW' | 'SETTLEMENT_CLEARING' | 'AUTO_LOAD';
  amount_paise: number;
  status: 'SUCCESS' | 'PENDING' | 'FAILED';
  reference: string;
  description: string | null;
  created_at: number;
}

export interface BankDetails {
  bankName: string;
  accountNumber: string;
  ifsc: string;
  upiVpa: string;
  infiniteMoney: boolean;
  bankBalancePaise: number;
  onlineBalancePaise: number;
}

export async function getOrCreateBankAccount(
  ctx: ServiceContext,
  accountId: string,
  phone: string,
  handle: string,
): Promise<MockBankAccountRow> {
  const existing = await ctx.db.get<MockBankAccountRow>('SELECT * FROM mock_bank_accounts WHERE account_id = ?', accountId);
  if (existing) return existing;

  const now = ctx.clock();
  const id = randomUUID();
  const accountNumber = `100${phone.replace(/^\+91/, '')}`;
  const upiVpa = `${handle.replace(/@dpay$/, '')}@mockbank`;
  const initialBalancePaise = 100_000_000_00; // ₹100,00,000 demo mock bank reserve

  await ctx.db.run(
    `INSERT INTO mock_bank_accounts (id, account_id, account_number, ifsc, bank_name, upi_vpa, infinite_money, balance_paise, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'ACTIVE', ?, ?)
     ON CONFLICT (account_number) DO NOTHING`,
    id,
    accountId,
    accountNumber,
    ctx.config.mockBank.ifsc,
    ctx.config.mockBank.name,
    upiVpa,
    initialBalancePaise,
    now,
    now,
  );

  return (await ctx.db.get<MockBankAccountRow>('SELECT * FROM mock_bank_accounts WHERE account_id = ?', accountId))!;
}

/**
 * Loads money from the mock bank account into the DPay online balance.
 * Assumes infinite money: loads always succeed up to requested amount!
 */
export async function loadMoney(
  ctx: ServiceContext,
  session: Session,
  amountPaise: number,
  clientRef?: string,
): Promise<{
  success: boolean;
  amountPaise: number;
  newOnlineBalancePaise: number;
  bankRef: string;
  message: string;
}> {
  if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) {
    throw new BankException(BankError.INVALID_REQUEST, 'amount must be a positive integer in paise');
  }

  const account = await requireAccount(ctx, session);
  const now = ctx.clock();
  const bankAccount = await getOrCreateBankAccount(ctx, account.id, account.phone, account.handle);
  const bankRef = clientRef ?? `MB-LOAD-${ctx.random(8).toString('hex').toUpperCase()}`;

  return await ctx.db.transaction(async () => {
    const newBalance = await postLedger(
      ctx.db,
      account.id,
      LedgerKind.BANK_LOAD,
      amountPaise,
      `mock_bank:${bankRef}`,
      now,
    );

    await ctx.db.run(
      `INSERT INTO mock_bank_transactions (account_id, bank_account_id, type, amount_paise, status, reference, description, created_at)
       VALUES (?, ?, 'LOAD', ?, 'SUCCESS', ?, 'Loaded into DPay online wallet from Mock Bank', ?)`,
      account.id,
      bankAccount.id,
      amountPaise,
      bankRef,
      now,
    );

    ctx.logger.info('money loaded from mock bank', {
      phone: account.phone,
      amountPaise,
      newBalance,
      bankRef,
    });

    return {
      success: true,
      amountPaise,
      newOnlineBalancePaise: newBalance,
      bankRef,
      message: `Successfully loaded ₹${(amountPaise / 100).toFixed(2)} from ${bankAccount.bank_name}`,
    };
  });
}

/**
 * Settles/withdraws funds from DPay online balance back to the mock bank account.
 */
export async function withdrawToBank(
  ctx: ServiceContext,
  session: Session,
  amountPaise: number,
  clientRef?: string,
): Promise<{
  success: boolean;
  amountPaise: number;
  remainingOnlineBalancePaise: number;
  bankRef: string;
  message: string;
}> {
  if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) {
    throw new BankException(BankError.INVALID_REQUEST, 'amount must be a positive integer in paise');
  }

  const account = await requireAccount(ctx, session);
  const now = ctx.clock();
  const bankAccount = await getOrCreateBankAccount(ctx, account.id, account.phone, account.handle);
  const bankRef = clientRef ?? `MB-WDR-${ctx.random(8).toString('hex').toUpperCase()}`;

  return await ctx.db.transaction(async () => {
    const fresh = await ctx.db.get<{ online_balance_paise: number }>('SELECT online_balance_paise FROM accounts WHERE id = ?', account.id);
    if (!fresh || fresh.online_balance_paise < amountPaise) {
      throw new BankException(BankError.INSUFFICIENT_BALANCE, 'insufficient online balance to withdraw to bank');
    }

    const remainingBalance = await postLedger(
      ctx.db,
      account.id,
      LedgerKind.BANK_WITHDRAW,
      -amountPaise,
      `mock_bank:${bankRef}`,
      now,
    );

    await ctx.db.run(
      `INSERT INTO mock_bank_transactions (account_id, bank_account_id, type, amount_paise, status, reference, description, created_at)
       VALUES (?, ?, 'WITHDRAW', ?, 'SUCCESS', ?, 'Settlement payout to Mock Bank account', ?)`,
      account.id,
      bankAccount.id,
      amountPaise,
      bankRef,
      now,
    );

    ctx.logger.info('settlement withdrawn to mock bank', {
      phone: account.phone,
      amountPaise,
      remainingBalance,
      bankRef,
    });

    return {
      success: true,
      amountPaise,
      remainingOnlineBalancePaise: remainingBalance,
      bankRef,
      message: `Successfully withdrawn ₹${(amountPaise / 100).toFixed(2)} to ${bankAccount.bank_name} A/C ${bankAccount.account_number}`,
    };
  });
}

/**
 * Automatically funds any shortfall when loading offline notes, if infinite money mode is active.
 * Returns the amount funded (0 if none needed).
 */
export async function autoFundShortfall(
  ctx: ServiceContext,
  accountId: string,
  requiredPaise: number,
  now: number,
): Promise<number> {
  if (!ctx.config.mockBank.autoLoad || !ctx.config.mockBank.infiniteMoney) return 0;

  const row = await ctx.db.get<{ online_balance_paise: number; phone: string; handle: string }>(
    'SELECT online_balance_paise, phone, handle FROM accounts WHERE id = ?',
    accountId,
  );
  if (!row) return 0;

  const current = row.online_balance_paise;
  if (current >= requiredPaise) return 0;

  const shortfall = requiredPaise - current;
  const bankAccount = await getOrCreateBankAccount(ctx, accountId, row.phone, row.handle);
  const bankRef = `MB-AUTO-${ctx.random(6).toString('hex').toUpperCase()}`;

  await postLedger(ctx.db, accountId, LedgerKind.BANK_AUTO_LOAD, shortfall, `mock_bank:${bankRef}`, now);

  await ctx.db.run(
    `INSERT INTO mock_bank_transactions (account_id, bank_account_id, type, amount_paise, status, reference, description, created_at)
     VALUES (?, ?, 'AUTO_LOAD', ?, 'SUCCESS', ?, 'Infinite money auto-topup for offline wallet load', ?)`,
    accountId,
    bankAccount.id,
    shortfall,
    bankRef,
    now,
  );

  ctx.logger.info('infinite money auto-topup', { accountId, shortfall, requiredPaise });
  return shortfall;
}

/**
 * Returns mock bank account details and balances for the authenticated user.
 */
export async function getBankDetails(ctx: ServiceContext, session: Session): Promise<BankDetails> {
  const account = await requireAccount(ctx, session);
  const bankAccount = await getOrCreateBankAccount(ctx, account.id, account.phone, account.handle);
  const fresh = await ctx.db.get<{ online_balance_paise: number }>('SELECT online_balance_paise FROM accounts WHERE id = ?', account.id);

  return {
    bankName: bankAccount.bank_name,
    accountNumber: bankAccount.account_number,
    ifsc: bankAccount.ifsc,
    upiVpa: bankAccount.upi_vpa,
    infiniteMoney: Boolean(bankAccount.infinite_money),
    bankBalancePaise: bankAccount.balance_paise,
    onlineBalancePaise: fresh?.online_balance_paise ?? 0,
  };
}

/**
 * Returns transaction history for the user's mock bank activities.
 */
export async function getBankTransactions(ctx: ServiceContext, session: Session, limit = 50) {
  const account = await requireAccount(ctx, session);
  const rows = await ctx.db.all<MockBankTransactionRow>(
    `SELECT * FROM mock_bank_transactions WHERE account_id = ? ORDER BY id DESC LIMIT ?`,
    account.id,
    limit,
  );
  return rows.map((r) => ({
    id: r.id,
    type: r.type,
    amountPaise: r.amount_paise,
    status: r.status,
    reference: r.reference,
    description: r.description,
    createdAt: r.created_at,
  }));
}

