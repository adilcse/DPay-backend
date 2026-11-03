import { createHash, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { AttestationError } from './verifier.ts';

/**
 * Play Integrity cross-check (PROTOCOL.md provisioning rule 8).
 *
 * The app requests a *standard* integrity token with
 * `requestHash = integrityRequestHash(challenge, identityPublicKey)` and sends it with the
 * certify-wallet call. `MEETS_STRONG_INTEGRITY` gets the full offline limit;
 * `MEETS_DEVICE_INTEGRITY` only gets the reduced limit.
 */
export type IntegrityTier = 'STRONG' | 'DEVICE' | 'UNCHECKED';

export interface IntegrityVerifier {
  readonly enforcing: boolean;
  verify(token: string | undefined, expectedRequestHash: string): Promise<IntegrityTier>;
}

/** Hex SHA-256 over `"DPAY/v1/integrity" ‖ 0x00 ‖ challenge ‖ identityKey`. */
export function integrityRequestHash(challenge: Buffer, identityPublicKey: Buffer): string {
  return createHash('sha256')
    .update('DPAY/v1/integrity', 'utf8')
    .update(Buffer.from([0]))
    .update(challenge)
    .update(identityPublicKey)
    .digest('hex');
}

export class DisabledIntegrityVerifier implements IntegrityVerifier {
  readonly enforcing = false;
  async verify(): Promise<IntegrityTier> {
    return 'UNCHECKED';
  }
}

interface ServiceAccount {
  client_email: string;
  private_key: string;
}

const MAX_TOKEN_AGE_MS = 10 * 60 * 1000;

/** Decodes tokens with Google's `decodeIntegrityToken` API using a service account. */
export class GooglePlayIntegrityVerifier implements IntegrityVerifier {
  readonly enforcing = true;
  private readonly account: ServiceAccount;
  private readonly packageName: string;
  private accessToken: { value: string; expiresAt: number } | null = null;

  constructor(serviceAccountFile: string, packageName: string) {
    this.account = JSON.parse(readFileSync(serviceAccountFile, 'utf8')) as ServiceAccount;
    if (!this.account.client_email || !this.account.private_key) throw new Error('invalid Play Integrity service account file');
    this.packageName = packageName;
  }

  async verify(token: string | undefined, expectedRequestHash: string): Promise<IntegrityTier> {
    if (!token) throw new AttestationError('Play Integrity token required');
    const res = await fetch(
      `https://playintegrity.googleapis.com/v1/${encodeURIComponent(this.packageName)}:decodeIntegrityToken`,
      {
        method: 'POST',
        headers: { authorization: `Bearer ${await this.token()}`, 'content-type': 'application/json' },
        body: JSON.stringify({ integrity_token: token }),
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) throw new AttestationError(`Play Integrity decode failed (HTTP ${res.status})`);
    const payload = ((await res.json()) as { tokenPayloadExternal?: IntegrityPayload }).tokenPayloadExternal;
    if (!payload) throw new AttestationError('empty Play Integrity verdict');

    const req = payload.requestDetails ?? {};
    if (req.requestPackageName !== this.packageName) throw new AttestationError('integrity token for another package');
    if (req.requestHash !== expectedRequestHash) throw new AttestationError('integrity token request hash mismatch');
    if (!req.timestampMillis || Math.abs(Date.now() - Number(req.timestampMillis)) > MAX_TOKEN_AGE_MS) {
      throw new AttestationError('stale integrity token');
    }
    if (payload.appIntegrity?.appRecognitionVerdict !== 'PLAY_RECOGNIZED') throw new AttestationError('app not recognized by Play');
    const device = payload.deviceIntegrity?.deviceRecognitionVerdict ?? [];
    if (device.includes('MEETS_STRONG_INTEGRITY')) return 'STRONG';
    if (device.includes('MEETS_DEVICE_INTEGRITY')) return 'DEVICE';
    throw new AttestationError('device does not meet integrity requirements');
  }

  private async token(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (this.accessToken && this.accessToken.expiresAt > now + 60) return this.accessToken.value;
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const claims = Buffer.from(
      JSON.stringify({
        iss: this.account.client_email,
        scope: 'https://www.googleapis.com/auth/playintegrity',
        aud: 'https://oauth2.googleapis.com/token',
        iat: now,
        exp: now + 3600,
      }),
    ).toString('base64url');
    const signature = createSign('RSA-SHA256').update(`${header}.${claims}`).sign(this.account.private_key).toString('base64url');
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: `${header}.${claims}.${signature}`,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`Google OAuth token request failed (HTTP ${res.status})`);
    const body = (await res.json()) as { access_token: string; expires_in: number };
    this.accessToken = { value: body.access_token, expiresAt: now + body.expires_in };
    return body.access_token;
  }
}

interface IntegrityPayload {
  requestDetails?: { requestPackageName?: string; requestHash?: string; timestampMillis?: string };
  appIntegrity?: { appRecognitionVerdict?: string };
  deviceIntegrity?: { deviceRecognitionVerdict?: string[] };
}
