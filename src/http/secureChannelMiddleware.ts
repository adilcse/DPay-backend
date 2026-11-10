import type { NextFunction, Request, Response } from 'express';
import { BankError, BankException } from '../domain/errors.ts';
import {
  deriveChannelKeys,
  decryptRequestEnvelope,
  encryptResponseEnvelope,
  EncryptedRequestSchema,
  parsePublicKey,
  SecureChannelConstants,
} from '../protocol/secureChannel.ts';
import type { ServiceContext } from '../services/context.ts';
import { diffieHellman } from 'node:crypto';

export interface SecureChannelContext {
  serverKey: Buffer;
  requestId: string;
}

const inMemorySeenRequests = new Map<string, number>();

async function checkAndRecordNonce(ctx: ServiceContext, requestId: string): Promise<boolean> {
  const now = ctx.clock();
  try {
    if (ctx.redis?.client) {
      const res = await ctx.redis.client.set(
        `dpay:replay:${requestId}`,
        '1',
        'EX',
        SecureChannelConstants.REPLAY_TTL_SECONDS,
        'NX',
      );
      return res === 'OK';
    }
  } catch {
    // Fall back to in-memory check if Redis fails
  }

  // Prune old in-memory entries
  for (const [id, expiry] of inMemorySeenRequests) {
    if (expiry <= now) inMemorySeenRequests.delete(id);
  }
  if (inMemorySeenRequests.has(requestId)) {
    return false;
  }
  inMemorySeenRequests.set(requestId, now + SecureChannelConstants.REPLAY_TTL_SECONDS);
  return true;
}

/**
 * Express middleware that handles end-to-end payload encryption using Advance DHE (ECDH) + AES-256-GCM.
 * Automatically decrypts incoming encrypted requests and transparently encrypts responses.
 */
export function secureChannelMiddleware(ctx: ServiceContext) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Intercept res.json to encrypt response when secureChannel is active
    const originalJson = res.json.bind(res);
    res.json = (body: unknown): Response => {
      const channel = res.locals.secureChannel as SecureChannelContext | undefined;
      if (channel && channel.serverKey) {
        try {
          const encryptedEnvelope = encryptResponseEnvelope(
            body,
            channel.serverKey,
            res.statusCode,
            channel.requestId,
            ctx.clock(),
          );
          res.setHeader('X-DPay-Encrypted', 'true');
          return originalJson(encryptedEnvelope);
        } catch (err) {
          ctx.logger.error('failed to encrypt response envelope', { error: String(err) });
        }
      }
      return originalJson(body);
    };

    try {
      // 1. Check if request body is an encrypted envelope
      if (req.body && typeof req.body === 'object' && req.body._encrypted === true) {
        const parsed = EncryptedRequestSchema.safeParse(req.body);
        if (!parsed.success) {
          throw new BankException(BankError.INVALID_REQUEST, 'malformed encrypted envelope', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
          });
        }

        const envelope = parsed.data;

        // Replay attack protection
        const isFresh = await checkAndRecordNonce(ctx, envelope.requestId);
        if (!isFresh) {
          throw new BankException(BankError.INVALID_REQUEST, 'replay attack detected: request ID already used');
        }

        // Decrypt request using Advance DHE
        const decrypted = decryptRequestEnvelope(
          envelope,
          ctx.issuer.getPrivateKey(),
          req.method,
          req.path,
          ctx.clock(),
        );

        // Replace req.body with plaintext decrypted JSON payload
        req.body = decrypted.payload;
        res.locals.secureChannel = {
          serverKey: decrypted.serverKey,
          requestId: decrypted.requestId,
        } satisfies SecureChannelContext;

        return next();
      }

      // 2. Check if request is a GET (or bodyless) request carrying ephemeral key headers
      const ephHeader = req.header('x-dpay-ephemeral-key');
      const isEncryptedHeader = req.header('x-dpay-encrypted') === 'true';
      if (ephHeader && isEncryptedHeader) {
        const requestId = req.header('x-dpay-request-id') || `req-${ctx.clock()}-${Math.random().toString(36).slice(2)}`;
        const tsHeader = Number(req.header('x-dpay-timestamp') || ctx.clock());

        if (Math.abs(ctx.clock() - tsHeader) > SecureChannelConstants.CLOCK_SKEW_SECONDS) {
          throw new BankException(BankError.INVALID_REQUEST, 'request timestamp expired or out of allowed clock skew');
        }

        const isFresh = await checkAndRecordNonce(ctx, requestId);
        if (!isFresh) {
          throw new BankException(BankError.INVALID_REQUEST, 'replay attack detected: request ID already used');
        }

        const ephBytes = Buffer.from(ephHeader, 'base64');
        const clientKeyObj = parsePublicKey(ephBytes);
        const sharedSecret = Buffer.from(diffieHellman({ publicKey: clientKeyObj, privateKey: ctx.issuer.getPrivateKey() }));
        const { serverKey } = deriveChannelKeys(sharedSecret);

        res.locals.secureChannel = {
          serverKey,
          requestId,
        } satisfies SecureChannelContext;

        return next();
      }

      // Normal unencrypted request
      next();
    } catch (err) {
      next(err);
    }
  };
}
