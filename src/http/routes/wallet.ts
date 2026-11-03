import { Router } from 'express';
import { z } from 'zod';
import type { ServiceContext } from '../../services/context.ts';
import * as wallets from '../../services/wallets.ts';
import { requireSession, sessionOf } from '../middleware.ts';
import { base64Bytes, keyAttestationSchema, parse, toWire } from '../wire.ts';

const Certify = z.object({
  challenge: base64Bytes({ size: 16 }),
  identity: keyAttestationSchema,
  /** Play Integrity standard token (required when PLAY_INTEGRITY_MODE=enforce). */
  integrityToken: z.string().max(16 * 1024).optional(),
});

const IssueNotes = z.object({
  challenge: base64Bytes({ size: 16 }),
  values: z.array(z.number().int().positive()).min(1).max(16),
  keys: z.array(keyAttestationSchema).min(1).max(16),
});

export function provisioningRoutes(ctx: ServiceContext): Router {
  const router = Router();
  router.use(requireSession(ctx));

  /** BankApi.provisioningChallenge */
    router.post('/challenge', async (_req, res) => {
      res.json(toWire(await wallets.provisioningChallenge(ctx, sessionOf(res))));
    });

    return router;
  }

export function walletRoutes(ctx: ServiceContext): Router {
    const router = Router();
    router.use(requireSession(ctx));

    /** Offline wallet card / OfflineWallet screen: notes, lease, limits, security tier. */
      router.get('/', async (_req, res) => {
        res.json(toWire(await wallets.walletStatus(ctx, sessionOf(res))));
      });

      /** BankApi.certifyWallet */
      router.post('/certificate', async (req, res) => {
        const body = parse(Certify, req.body);
        res.status(201).json(toWire(await wallets.certifyWallet(ctx, sessionOf(res), body.challenge, body.identity, body.integrityToken)));
      });

      /** BankApi.issueNotes. Also returns the fresh lease covering the new notes. */
      router.post('/notes', async (req, res) => {
        const body = parse(IssueNotes, req.body);
        res.status(201).json(toWire(await wallets.issueNotes(ctx, sessionOf(res), body.challenge, body.values, body.keys)));
      });

      /** BankApi.refreshLease */
        router.post('/lease', async (_req, res) => {
          res.json(toWire(await wallets.refreshLease(ctx, sessionOf(res))));
        });

        return router;
      }
