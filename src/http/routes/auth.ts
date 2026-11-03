import { Router } from 'express';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';
import * as auth from '../../services/auth.ts';
import type { ServiceContext } from '../../services/context.ts';
import { requireSession, sessionOf } from '../middleware.ts';
import { deviceIdSchema, parse, phoneSchema, toWire } from '../wire.ts';

const OtpRequest = z.object({ phone: phoneSchema });
const OtpVerify = z.object({ phone: phoneSchema, code: z.string().regex(/^\d{6}$/), deviceId: deviceIdSchema.optional() });

export function authRoutes(ctx: ServiceContext): Router {
  const router = Router();
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: ctx.config.env === 'test' ? 10_000 : 30,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    validate: {
      trustProxy: false,
      xForwardedForHeader: false,
    },
    message: { error: { code: 'RATE_LIMITED', message: 'too many requests' } },
  });

  /** BankApi.requestOtp */
  router.post('/otp', limiter, async (req, res) => {
    const { phone } = parse(OtpRequest, req.body);
    res.json(toWire(await auth.requestOtp(ctx, phone)));
  });

  /** BankApi.verifyOtp. The device id comes from the body or the `X-Device-Id` header. */
    router.post('/otp/verify', limiter, async (req, res) => {
      const body = parse(OtpVerify, req.body);
      const deviceId = parse(deviceIdSchema, body.deviceId ?? req.header('x-device-id'));
      res.json(toWire(await auth.verifyOtp(ctx, body.phone, body.code, deviceId)));
    });

    /** BankApi.logout */
      router.post('/logout', requireSession(ctx), async (_req, res) => {
        await auth.logout(ctx, sessionOf(res));
        res.status(204).end();
      });

      return router;
    }
