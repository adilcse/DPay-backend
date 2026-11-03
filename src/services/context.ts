import { randomBytes } from 'node:crypto';
import type { IntegrityVerifier } from '../attestation/playIntegrity.ts';
import type { KeyAttestationVerifier } from '../attestation/verifier.ts';
import type { Config } from '../config.ts';
import type { Database } from '../db/database.ts';
import type { RedisService } from '../db/redis.ts';
import type { Logger } from '../lib/logger.ts';
import type { Issuer } from '../protocol/issuer.ts';
import type { SmsSender } from './sms.ts';

/** Everything the services need. */
export interface ServiceContext {
  readonly config: Config;
  readonly db: Database;
  readonly redis: RedisService;
  readonly issuer: Issuer;
  readonly attestation: KeyAttestationVerifier;
  readonly integrity: IntegrityVerifier;
  readonly sms: SmsSender;
  readonly logger: Logger;
  /** Epoch seconds. */
  readonly clock: () => number;
  readonly random: (size: number) => Buffer;
}

export const systemClock = (): number => Math.floor(Date.now() / 1000);
export const secureRandom = (size: number): Buffer => randomBytes(size);

export const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
export const unhex = (s: string): Buffer => Buffer.from(s, 'hex');
