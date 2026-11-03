import { Router } from 'express';
import { z } from 'zod';
import type { ServiceContext } from '../../services/context.ts';
import * as mockBank from '../../services/mockBank.ts';
import { requireSession, sessionOf } from '../middleware.ts';
import { parse, toWire } from '../wire.ts';

const LoadMoneySchema = z.object({
  amountPaise: z.number().int().positive().max(10_00_00_000_00), // Up to ₹10 Crore per load
  reference: z.string().max(100).optional(),
});

const WithdrawSchema = z.object({
  amountPaise: z.number().int().positive().max(10_00_00_000_00),
  reference: z.string().max(100).optional(),
});

export function bankRoutes(ctx: ServiceContext): Router {
  const router = Router();
  router.use(requireSession(ctx));

  /** Get linked mock bank account details, balance and infinite money status. */
  router.get('/account', async (_req, res) => {
    res.json(toWire(await mockBank.getBankDetails(ctx, sessionOf(res))));
  });

  /** Load money from mock bank into DPay online balance (Infinite Money). */
  router.post('/load', async (req, res) => {
    const body = parse(LoadMoneySchema, req.body);
    res.json(toWire(await mockBank.loadMoney(ctx, sessionOf(res), body.amountPaise, body.reference)));
  });

  /** Settle/withdraw online balance to mock bank account. */
  router.post('/withdraw', async (req, res) => {
    const body = parse(WithdrawSchema, req.body);
    res.json(toWire(await mockBank.withdrawToBank(ctx, sessionOf(res), body.amountPaise, body.reference)));
  });

  /** Transaction history of mock bank loads and settlement withdrawals. */
  router.get('/transactions', async (req, res) => {
    const limit = parse(z.coerce.number().int().min(1).max(100).default(50), req.query.limit);
    res.json({ transactions: toWire(await mockBank.getBankTransactions(ctx, sessionOf(res), limit)) });
  });

  return router;
}

