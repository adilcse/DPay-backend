import { Router } from 'express';
import { z } from 'zod';
import * as admin from '../../services/admin.ts';
import type { ServiceContext } from '../../services/context.ts';
import { runMaintenance } from '../../services/maintenance.ts';
import { requireAdmin } from '../middleware.ts';
import { parse, phoneSchema } from '../wire.ts';

export function adminRoutes(ctx: ServiceContext): Router {
  const router = Router();
  router.use(requireAdmin(ctx));

    router.post('/accounts/:phone/credit', async (req, res) => {
      const phone = parse(phoneSchema, req.params.phone);
      const body = parse(
        z.object({ amountPaise: z.number().int().positive().max(1_00_00_000_00), reference: z.string().max(100).optional() }),
        req.body,
      );
      res.json(await admin.creditAccount(ctx, phone, body.amountPaise, body.reference ?? null));
    });

      router.post('/accounts/:phone/freeze', async (req, res) => {
        res.json(await admin.setAccountFrozen(ctx, parse(phoneSchema, req.params.phone), true));
      });

        router.post('/accounts/:phone/unfreeze', async (req, res) => {
          res.json(await admin.setAccountFrozen(ctx, parse(phoneSchema, req.params.phone), false));
        });

          router.get('/fraud-events', async (req, res) => {
            const limit = parse(z.coerce.number().int().min(1).max(500).default(100), req.query.limit);
            res.json({ events: await admin.fraudEvents(ctx, limit) });
          });

            router.post('/maintenance', async (_req, res) => {
              res.json(await runMaintenance(ctx));
            });

            return router;
          }
