import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { BankError, BankException } from '../../domain/errors.ts';
import { base64Bytes, parse } from '../wire.ts';
import * as P256 from '../../protocol/p256.ts';
import { deriveChannelKeys, parsePublicKey, SecureChannelConstants } from '../../protocol/secureChannel.ts';
import type { ServiceContext } from '../../services/context.ts';

const HandshakeRequestSchema = z.object({
  clientEphemeralPublicKey: base64Bytes({ max: 128 }),
  clientNonce: base64Bytes({ size: 16 }),
  timestamp: z.number().int(),
});

export function cryptoRoutes(ctx: ServiceContext): Router {
  const router = Router();

  const handleHandshake = async (req: any, res: any, next: any) => {
    try {
      const body = parse(HandshakeRequestSchema, req.body);
      const now = ctx.clock();

      // 1. Freshness check
      if (Math.abs(now - body.timestamp) > SecureChannelConstants.CLOCK_SKEW_SECONDS) {
        throw new BankException(BankError.INVALID_REQUEST, 'handshake timestamp expired or clock skew exceeded');
      }

      // 2. Parse client ephemeral key
      const clientKeyObj = parsePublicKey(body.clientEphemeralPublicKey);

      // 3. Generate server ephemeral EC P-256 key pair
      const serverPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const serverPubCompressed = P256.compress(serverPair.publicKey);

      // 4. Compute Advance DHE shared secret
      const sharedSecret = Buffer.from(
        serverPair.privateKey.export({ format: 'der', type: 'pkcs8' }),
      );
      const ecdhSecret = Buffer.from(
        (await import('node:crypto')).diffieHellman({
          publicKey: clientKeyObj,
          privateKey: serverPair.privateKey,
        }),
      );

      // 5. Derive keys via HKDF-SHA256
      const { clientKey, serverKey } = deriveChannelKeys(ecdhSecret);

      // 6. Generate server nonce and channel ID
      const serverNonce = randomBytes(16);
      const channelId = createHash('sha256')
        .update(Buffer.concat([serverNonce, body.clientNonce, ecdhSecret]))
        .digest('hex')
        .slice(0, 32);

      // 7. Sign transcript with Issuer Key for server authentication (prevent MITM)
      const tsBuffer = Buffer.alloc(8);
      tsBuffer.writeBigInt64BE(BigInt(body.timestamp));
      const transcript = Buffer.concat([
        Buffer.from(SecureChannelConstants.HANDSHAKE_DOMAIN, 'utf8'),
        Buffer.from([0]),
        serverPubCompressed,
        body.clientEphemeralPublicKey,
        serverNonce,
        body.clientNonce,
        tsBuffer,
      ]);

      const signature = (await import('node:crypto')).sign('sha256', transcript, {
        key: ctx.issuer.getPrivateKey(),
        dsaEncoding: 'der',
      });

      // 8. Cache channel state in Redis (1 hour TTL)
      const sessionTtl = 3600;
      if (ctx.redis?.client) {
        await ctx.redis.client.set(
          `dpay:channel:${channelId}`,
          JSON.stringify({
            channelId,
            clientKey: clientKey.toString('base64'),
            serverKey: serverKey.toString('base64'),
            expiresAt: now + sessionTtl,
          }),
          'EX',
          sessionTtl,
        );
      }

      res.json({
        channelId,
        serverEphemeralPublicKey: serverPubCompressed.toString('base64'),
        serverNonce: serverNonce.toString('base64'),
        signature: signature.toString('base64'),
        keyId: ctx.issuer.keyId,
        expiresAt: now + sessionTtl,
      });
    } catch (err) {
      next(err);
    }
  };

  router.post('/handshake', handleHandshake);
  router.post('/exchange', handleHandshake);

  return router;
}
