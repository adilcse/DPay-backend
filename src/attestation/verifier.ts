import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as P256 from '../protocol/p256.ts';
import {
  AuthTag,
  findExtension,
  KEY_DESCRIPTION_OID,
  KM_ALGORITHM_EC,
  KM_EC_CURVE_P256,
  KM_PURPOSE_SIGN,
  parseKeyDescription,
  SecurityLevel,
  VerifiedBootState,
} from './keyDescription.ts';
import type { RevocationList } from './revocation.ts';

export class AttestationError extends Error {}

export type KeyKind = 'identity' | 'note';

export interface AttestationInput {
  /** Compressed P-256 public key the client claims for this key. */
  readonly publicKey: Buffer;
  /** DER certificates, leaf first. */
  readonly chain: readonly Buffer[];
  /** The single-use challenge the server issued for this session. */
  readonly challenge: Buffer;
  readonly kind: KeyKind;
}

export interface AttestationResult {
  readonly securityLevel: 'STRONG_BOX' | 'TRUSTED_ENVIRONMENT' | 'UNVERIFIED';
  /**
   * Note keys: whether `usageCountLimit == 1` is hardware-enforced (rollback resistant). If it's
   * only software-enforced (keystore2), the bank lowers the wallet's offline limit.
   */
  readonly usageLimitHardwareEnforced: boolean;
}

export interface KeyAttestationVerifier {
  readonly enforcing: boolean;
  verify(input: AttestationInput): Promise<AttestationResult>;
}

/**
 * Development only: accepts any chain (emulators and the app's software key store can't produce
 * hardware attestation). Mirrors the app's FakeBank. Production refuses to start in this mode.
 */
export class DisabledAttestationVerifier implements KeyAttestationVerifier {
  readonly enforcing = false;

  async verify(): Promise<AttestationResult> {
    return { securityLevel: 'UNVERIFIED', usageLimitHardwareEnforced: true };
  }
}

export interface AndroidAttestationOptions {
  /** Google hardware attestation root certificates. */
  readonly roots: readonly X509Certificate[];
  readonly packageName: string;
  /** Release signing certificate SHA-256 digests (lowercase hex). */
  readonly signingCertDigests: readonly string[];
  readonly revocation: RevocationList;
  readonly now?: () => Date;
}

const MAX_CHAIN_LENGTH = 10;

/** Implements PROTOCOL.md "Provisioning: verify every attestation chain", rules 1–7. */
export class AndroidKeyAttestationVerifier implements KeyAttestationVerifier {
  readonly enforcing = true;
  private readonly options: AndroidAttestationOptions;
  private readonly rootSpkis: Buffer[];

  constructor(options: AndroidAttestationOptions) {
    if (options.roots.length === 0) throw new Error('no attestation roots configured');
    if (options.signingCertDigests.length === 0) throw new Error('no app signing certificate digests configured');
    this.options = options;
    this.rootSpkis = options.roots.map((r) => r.publicKey.export({ format: 'der', type: 'spki' }));
  }

  static loadRoots(pemBundlePath: string): X509Certificate[] {
    const pem = readFileSync(pemBundlePath, 'utf8');
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
    return blocks.map((b) => new X509Certificate(b));
  }

  async verify(input: AttestationInput): Promise<AttestationResult> {
    const fail = (msg: string): never => {
      throw new AttestationError(`${input.kind} key attestation: ${msg}`);
    };
    if (input.chain.length < 2 || input.chain.length > MAX_CHAIN_LENGTH) fail('bad chain length');

    let certs: X509Certificate[] = [];
    try {
      certs = input.chain.map((d) => new X509Certificate(d));
    } catch {
      fail('unparseable certificate');
    }
    const now = (this.options.now ?? (() => new Date()))();

    // 1. Chain to a Google root, every link signed by the next; nothing revoked.
    for (let i = 0; i < certs.length - 1; i++) {
      const child = certs[i]!;
      const parent = certs[i + 1]!;
      if (!child.verify(parent.publicKey)) fail(`certificate ${i} is not signed by its issuer`);
      // KeyMint leaf validity is often unset or far-future; check the CA certificates only.
      if (now < new Date(parent.validFrom) || now > new Date(parent.validTo)) {
        fail(`certificate ${i + 1} is outside its validity period`);
      }
    }
    const top = certs[certs.length - 1]!;
    const topSpki = top.publicKey.export({ format: 'der', type: 'spki' });
    const anchored =
      this.rootSpkis.some((root) => root.equals(topSpki) && top.verify(top.publicKey)) ||
      this.options.roots.some((root) => top.verify(root.publicKey));
    if (!anchored) fail('chain does not end at a Google hardware attestation root');
    for (const cert of certs) {
      let revoked: boolean;
      try {
        revoked = await this.options.revocation.isRevoked(cert.serialNumber);
      } catch {
        throw new AttestationError('attestation revocation status unavailable');
      }
      if (revoked) fail('a certificate in the chain is revoked');
    }

    // The leaf must certify exactly the key the client claims.
    const leaf = certs[0]!;
    let leafKey: Buffer = Buffer.alloc(0);
    try {
      leafKey = P256.compress(leaf.publicKey);
    } catch {
      fail('leaf key is not P-256');
    }
    if (!leafKey.equals(input.publicKey)) fail('leaf certificate is for a different key');

    const extension = findExtension(input.chain[0]!, KEY_DESCRIPTION_OID) ?? fail('missing key description extension');
    let kd: ReturnType<typeof parseKeyDescription>;
    try {
      kd = parseKeyDescription(extension);
    } catch (e) {
      return fail(`malformed key description (${(e as Error).message})`);
    }
    const hw = kd.hardwareEnforced;
    const sw = kd.softwareEnforced;

    // 2. Challenge.
    if (!kd.attestationChallenge.equals(input.challenge)) fail('challenge mismatch');

    // 3. Security levels.
    const isHardware = (level: number) => level === SecurityLevel.TRUSTED_ENVIRONMENT || level === SecurityLevel.STRONG_BOX;
    if (!isHardware(kd.attestationSecurityLevel) || !isHardware(kd.keyMintSecurityLevel)) fail('key is not hardware backed');

    // 4. Verified boot, locked bootloader.
    const rot = hw.rootOfTrust() ?? fail('missing root of trust');
    if (rot.verifiedBootState !== VerifiedBootState.VERIFIED) fail('verified boot state is not Verified');
    if (!rot.deviceLocked) fail('bootloader is unlocked');

    // 5. Our app, signed with our release key.
    const appId = sw.attestationApplicationId() ?? hw.attestationApplicationId() ?? fail('missing attestation application id');
    if (!appId.packageNames.includes(this.options.packageName)) fail('wrong package name');
    if (!appId.signatureDigests.some((d) => this.options.signingCertDigests.includes(d))) fail('wrong app signing certificate');

    // 6. Key properties: EC P-256, SIGN only, user auth required, unlocked device required.
    if (hw.int(AuthTag.ALGORITHM) !== KM_ALGORITHM_EC) fail('not an EC key');
    const curve = hw.int(AuthTag.EC_CURVE);
    if (curve !== undefined && curve !== KM_EC_CURVE_P256) fail('not a P-256 key');
    const purposes = hw.intSet(AuthTag.PURPOSE) ?? [];
    if (purposes.length === 0 || purposes.some((p) => p !== KM_PURPOSE_SIGN)) fail('key purpose must be SIGN only');
    if (hw.has(AuthTag.NO_AUTH_REQUIRED) || sw.has(AuthTag.NO_AUTH_REQUIRED)) fail('key does not require user authentication');
    if (!hw.has(AuthTag.UNLOCKED_DEVICE_REQUIRED) && !sw.has(AuthTag.UNLOCKED_DEVICE_REQUIRED)) fail('key does not require an unlocked device');

    // 7. Note keys must be single use.
    let usageLimitHardwareEnforced = true;
    if (input.kind === 'note') {
      if (hw.int(AuthTag.USAGE_COUNT_LIMIT) === 1) usageLimitHardwareEnforced = true;
      else if (sw.int(AuthTag.USAGE_COUNT_LIMIT) === 1) usageLimitHardwareEnforced = false;
      else fail('note key is not single use (usageCountLimit != 1)');
    }

    return {
      securityLevel: kd.keyMintSecurityLevel === SecurityLevel.STRONG_BOX ? 'STRONG_BOX' : 'TRUSTED_ENVIRONMENT',
      usageLimitHardwareEnforced,
    };
  }
}
