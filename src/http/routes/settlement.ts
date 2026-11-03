import { Router } from 'express';
import { z } from 'zod';
import { BankError, BankException } from '../../domain/errors.ts';
import { Limits } from '../../domain/limits.ts';
import * as account from '../../services/account.ts';
import type { ServiceContext } from '../../services/context.ts';
import * as settlement from '../../services/settlement.ts';
import { requireSession, sessionOf } from '../middleware.ts';
import { base64Bytes, parse, toWire } from '../wire.ts';

const payment = base64Bytes({ max: 64 * 1024 });
const Upload = z.object({
  received: z.array(z.object({ payment, receivedAt: z.number().int().nonnegative() })).max(Limits.MAX_SETTLEMENT_ITEMS).default([]),
  sent: z.array(payment).max(Limits.MAX_SETTLEMENT_ITEMS).default([]),
});

export function settlementRoutes(ctx: ServiceContext): Router {
  const router = Router();
  // Mounted at the /v1 root, so authenticate per route (unknown paths must still 404).
  const session = requireSession(ctx);

  /** BankApi.settle */
    router.post('/settlement', session, async (req, res) => {
      const upload = parse(Upload, req.body);
      res.json(toWire(await settlement.settle(ctx, sessionOf(res), upload)));
    });

    /** TransactionDetail: settlement status of one payment (16-byte id, hex or base64url). */
      router.get('/payments/:paymentId', session, async (req, res) => {
        const raw = req.params.paymentId;
        if (typeof raw !== 'string') throw new BankException(BankError.INVALID_REQUEST, 'missing payment id');
        const id = /^[0-9a-f]{32}$/i.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64url');
        if (id.length !== 16) throw new BankException(BankError.INVALID_REQUEST, 'payment id must be 16 bytes');
        const status = await settlement.paymentStatus(ctx, sessionOf(res), id);
        if (!status) {
          res.json(toWire({ paymentId: id, status: 'PENDING' }));
          return;
        }
        res.json(toWire(status));
      });

      /** BankApi.account */
        router.get('/account', session, async (_req, res) => {
          res.json(await account.accountSummary(ctx, sessionOf(res)));
        });

        /** History: online ledger entries (loads, settled payments, refunds), newest first. */
          router.get('/transactions', session, async (req, res) => {
            const q = parse(
              z.object({
                limit: z.coerce.number().int().min(1).max(100).default(50),
                before: z.coerce.number().int().positive().optional(),
              }),
              req.query,
            );
            res.json(toWire(await account.transactions(ctx, sessionOf(res), q.limit, q.before)));
          });

          /** Receivers' `isWalletBlocked` list. */
            router.get('/blocklist', session, async (_req, res) => {
              res.json(toWire(await account.blocklist(ctx)));
            });

            return router;
          }
