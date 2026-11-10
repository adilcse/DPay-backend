import { DisabledIntegrityVerifier, GooglePlayIntegrityVerifier } from './attestation/playIntegrity.ts';
import { GoogleRevocationList } from './attestation/revocation.ts';
import { AndroidKeyAttestationVerifier, DisabledAttestationVerifier } from './attestation/verifier.ts';
import type { Config } from './config.ts';
import { Database } from './db/database.ts';
import { RedisService } from './db/redis.ts';
import type { Logger } from './lib/logger.ts';
import { Issuer } from './protocol/issuer.ts';
import { secureRandom, systemClock, type ServiceContext } from './services/context.ts';
import { createSmsSender } from './services/sms.ts';

/** Wires the real dependencies from configuration. */
  export async function createContext(config: Config, logger: Logger): Promise<ServiceContext> {
    const issuer = config.issuerKeyFile ? Issuer.fromPemFile(config.issuerKeyFile, config.issuerKeyId) : Issuer.demo();
    if (issuer.isDemoKey) {
      logger.warn('using the PUBLIC demo issuer key (FakeIssuer); anyone can forge notes. Set ISSUER_KEY_FILE for real money.');
    }
    if (config.env === 'production' && (config.mockBank.infiniteMoney || config.mockBank.autoLoad)) {
      logger.warn(
        'MOCK BANK is on in production: balances are created from nothing (MOCK_BANK_INFINITE_MONEY / MOCK_BANK_AUTO_LOAD). ' +
          'Acceptable for a proof of concept only; turn both off before real money is involved.',
      );
    }
    const attestation =
      config.attestation.mode === 'enforce'
        ? new AndroidKeyAttestationVerifier({
          roots: AndroidKeyAttestationVerifier.loadRoots(config.attestation.rootsFile!),
          packageName: config.attestation.packageName,
          signingCertDigests: config.attestation.signingCertDigests,
          revocation: new GoogleRevocationList(logger),
        })
        : new DisabledAttestationVerifier();
    if (!attestation.enforcing) logger.warn('key attestation is NOT verified (ATTESTATION_MODE=off); development only');

    const integrity =
      config.playIntegrity.mode === 'enforce'
        ? new GooglePlayIntegrityVerifier(config.playIntegrity.serviceAccountFile!, config.attestation.packageName)
        : new DisabledIntegrityVerifier();

    const db = new Database(config.databaseUrl);
    await db.init();

    const redis = new RedisService(config.redisUrl, logger);

    return {
      config,
      db,
      redis,
      issuer,
      attestation,
      integrity,
      sms: createSmsSender(config, logger),
      logger,
      clock: systemClock,
      random: secureRandom,
    };
  }
