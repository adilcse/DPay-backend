import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { BankError, BankException } from '../domain/errors.ts';
import { maskPhone, type Logger } from '../lib/logger.ts';
import { authenticate, type Session } from '../services/auth.ts';
import type { ServiceContext } from '../services/context.ts';

export function bearerToken(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return undefined;
  return header.slice(7).trim() || undefined;
}

/** Requires `Authorization: Bearer <session>`; puts the session in `res.locals.session`. */
export function requireSession(ctx: ServiceContext) {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        res.locals.session = await authenticate(ctx, bearerToken(req));
        next();
      } catch (err) {
        next(err);
      }
    };
  }

  export const sessionOf = (res: Response): Session => res.locals.session as Session;

  /** Back-office endpoints: `X-Admin-Key`. Disabled entirely when ADMIN_API_KEY is unset. */
  export function requireAdmin(ctx: ServiceContext) {
    return (req: Request, _res: Response, next: NextFunction) => {
      const expected = ctx.config.adminApiKey;
      const given = req.header('x-admin-key');
      if (!expected) throw new BankException(BankError.NOT_FOUND);
      const a = Buffer.from(given ?? '');
      const b = Buffer.from(expected);
      if (a.length !== b.length || !timingSafeEqual(a, b)) throw new BankException(BankError.FORBIDDEN);
      next();
    };
  }

  /** Request path for logs: no query string, and phone numbers in the path (admin routes) masked. */
  export const loggedPath = (req: Request): string =>
    (req.originalUrl ? req.originalUrl.split('?')[0]! : req.path).replace(/\/accounts\/(\d{6,})(?=\/|$)/, (_m, phone: string) => `/accounts/${maskPhone(phone)}`);

  export function requestLogger(logger: Logger) {
    return (req: Request, res: Response, next: NextFunction) => {
      const start = process.hrtime.bigint();
      res.on('finish', () => {
        logger.info('request', {
          method: req.method,
          path: loggedPath(req),
          status: res.statusCode,
          ms: Number((process.hrtime.bigint() - start) / 1_000_000n),
        });
      });
      next();
    };
  }

  export function errorHandler(logger: Logger) {
    return (err: unknown, req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof BankException) {
        logger.warn('bank exception', {
          path: loggedPath(req),
          status: err.status,
          code: err.code,
          message: err.message,
          ...(err.details ? { details: err.details } : {}),
        });
        res.status(err.status).json({ error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) } });
        return;
      }
      const e = err as { type?: string; status?: number; message?: string };
      if (e?.type === 'entity.too.large') {
        res.status(413).json({ error: { code: BankError.INVALID_REQUEST, message: 'request body too large' } });
        return;
      }
      if (e?.type === 'entity.parse.failed') {
        res.status(400).json({ error: { code: BankError.INVALID_REQUEST, message: 'malformed JSON' } });
        return;
      }
      logger.error('unhandled error', { error: err instanceof Error ? err.stack ?? err.message : String(err) });
      res.status(500).json({ error: { code: BankError.INTERNAL, message: 'internal error' } });
    };
  }
