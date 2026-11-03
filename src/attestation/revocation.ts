import type { Logger } from '../lib/logger.ts';

/** Google's attestation certificate revocation list (PROTOCOL.md, provisioning rule 1). */
export const GOOGLE_ATTESTATION_STATUS_URL = 'https://android.googleapis.com/attestation/status';

export interface RevocationList {
  /** True if any certificate serial (hex) is revoked or suspended. Throws if no list is available (fail closed). */
  isRevoked(serialHex: string): Promise<boolean>;
}

export function normalizeSerial(serialHex: string): string {
  return serialHex.toLowerCase().replace(/^0+(?=.)/, '');
}

/** Fetches and caches the status list; keeps serving the last good copy if a refresh fails. */
export class GoogleRevocationList implements RevocationList {
  private entries: Set<string> | null = null;
  private fetchedAt = 0;
  private inflight: Promise<void> | null = null;
  private readonly url: string;
  private readonly ttlMs: number;
  private readonly logger: Logger;

  constructor(logger: Logger, url = GOOGLE_ATTESTATION_STATUS_URL, ttlMs = 60 * 60 * 1000) {
    this.logger = logger;
    this.url = url;
    this.ttlMs = ttlMs;
  }

  async isRevoked(serialHex: string): Promise<boolean> {
    if (!this.entries || Date.now() - this.fetchedAt > this.ttlMs) {
      this.inflight ??= this.refresh().finally(() => {
        this.inflight = null;
      });
      await this.inflight;
    }
    if (!this.entries) throw new Error('attestation revocation list unavailable');
    return this.entries.has(normalizeSerial(serialHex));
  }

  private async refresh(): Promise<void> {
    try {
      const res = await fetch(this.url, { headers: { 'cache-control': 'no-cache' }, signal: AbortSignal.timeout(10_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { entries?: Record<string, unknown> };
      this.entries = new Set(Object.keys(body.entries ?? {}).map(normalizeSerial));
      this.fetchedAt = Date.now();
      this.logger.info('attestation revocation list refreshed', { entries: this.entries.size });
    } catch (e) {
      this.logger.error('attestation revocation list refresh failed', { error: String(e) });
    }
  }
}
