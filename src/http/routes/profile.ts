import { Router } from 'express';
import { z } from 'zod';
import * as accounts from '../../services/accounts.ts';
import type { ServiceContext } from '../../services/context.ts';
import { requireSession, sessionOf } from '../middleware.ts';
import { emailSchema, fullNameSchema, parse, toWire } from '../wire.ts';

const Register = z.object({ fullName: fullNameSchema, handle: z.string().max(40), email: emailSchema });
const Update = z.object({ fullName: fullNameSchema, email: emailSchema });

export function handleRoutes(ctx: ServiceContext): Router {
  const router = Router();

  /** BankApi.isHandleAvailable: `?handle=asha.rao` or `asha.rao@dpay`. */
    router.get('/availability', async (req, res) => {
      const handle = parse(z.string().min(1).max(40), req.query.handle);
      res.json({ handle, available: await accounts.isHandleAvailable(ctx, handle) });
    });

    /** Suggests a free handle from the user's name (ProfileSetup). */
      router.get('/suggestion', async (req, res) => {
        const fullName = parse(fullNameSchema, req.query.fullName);
        res.json({ suggestion: await accounts.suggestAvailableHandle(ctx, fullName) });
      });

      return router;
    }

export function profileRoutes(ctx: ServiceContext): Router {
      const router = Router();
      router.use(requireSession(ctx));

      /** BankApi.register: creates the account for a new user (after OTP). */
        router.post('/', async (req, res) => {
          const body = parse(Register, req.body);
          res.status(201).json(toWire(await accounts.register(ctx, sessionOf(res), body.fullName, body.handle, body.email)));
        });

        /** BankApi.profile */
          router.get('/', async (_req, res) => {
            res.json(toWire(accounts.toProfile(await accounts.requireAccount(ctx, sessionOf(res)))));
          });

          /** BankApi.updateProfile */
            router.patch('/', async (req, res) => {
              const body = parse(Update, req.body);
              res.json(toWire(await accounts.updateProfile(ctx, sessionOf(res), body.fullName, body.email)));
            });

            return router;
          }

export function deviceRoutes(ctx: ServiceContext): Router {
            const router = Router();
            router.use(requireSession(ctx));

            /** BankApi.moveToThisDevice: binds the account here and deregisters the previous device. */
              router.post('/move', async (_req, res) => {
                await accounts.moveToThisDevice(ctx, sessionOf(res));
                res.status(204).end();
              });

              return router;
            }
