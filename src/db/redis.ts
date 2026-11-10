import { Redis } from 'ioredis';
import type { Logger } from '../lib/logger.ts';

export interface CachedSession {
  phone: string;
  deviceId: string;
  expiresAt: number;
  lastSeenAt: number;
}

export interface CachedOtp {
  codeHash: string;
  expiresAt: number;
  resendAt: number;
  attempts: number;
  windowStart: number;
  sendsInWindow: number;
}

export class RedisService {
  readonly client: Redis;
  private readonly logger: Logger;

  constructor(redisUrl: string, logger: Logger) {
    this.logger = logger;
    this.client = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => Math.min(times * 100, 3000),
      lazyConnect: false,
    });

    this.client.on('error', (err) => {
      this.logger.error('redis error', { error: String(err) });
    });
  }

  async ping(): Promise<boolean> {
    try {
      const pong = await this.client.ping();
      return pong === 'PONG';
    } catch {
      return false;
    }
  }

  // --- Sessions ----------------------------------------------------------------------------------

  async getSession(tokenHash: string): Promise<CachedSession | null> {
    try {
      const data = await this.client.get(`session:${tokenHash}`);
      return data ? JSON.parse(data) : null;
    } catch (e) {
      this.logger.warn('redis getSession failed', { error: String(e) });
      return null;
    }
  }

  async setSession(tokenHash: string, session: CachedSession, ttlSeconds: number): Promise<void> {
    try {
      await this.client.set(`session:${tokenHash}`, JSON.stringify(session), 'EX', ttlSeconds);
    } catch (e) {
      this.logger.warn('redis setSession failed', { error: String(e) });
    }
  }

  async deleteSession(tokenHash: string): Promise<void> {
    try {
      await this.client.del(`session:${tokenHash}`);
    } catch (e) {
      this.logger.warn('redis deleteSession failed', { error: String(e) });
    }
  }

  /**
   * Updates a cached session in place. `XX` + `KEEPTTL` make this a single atomic command: a
   * session revoked between the caller's read and this write is not put back, and the entry keeps
   * its original (short) lifetime so PostgreSQL is re-checked regularly.
   */
  async touchSession(tokenHash: string, session: CachedSession): Promise<void> {
    try {
      await this.client.set(`session:${tokenHash}`, JSON.stringify(session), 'KEEPTTL', 'XX');
    } catch (e) {
      this.logger.warn('redis touchSession failed', { error: String(e) });
    }
  }

  // --- OTPs --------------------------------------------------------------------------------------

  async getOtp(phone: string): Promise<CachedOtp | null> {
    try {
      const data = await this.client.get(`otp:${phone}`);
      return data ? JSON.parse(data) : null;
    } catch (e) {
      this.logger.warn('redis getOtp failed', { error: String(e) });
      return null;
    }
  }

  async setOtp(phone: string, otp: CachedOtp, ttlSeconds: number): Promise<void> {
    try {
      await this.client.set(`otp:${phone}`, JSON.stringify(otp), 'EX', ttlSeconds);
    } catch (e) {
      this.logger.warn('redis setOtp failed', { error: String(e) });
    }
  }

  async deleteOtp(phone: string): Promise<void> {
    try {
      await this.client.del(`otp:${phone}`);
    } catch (e) {
      this.logger.warn('redis deleteOtp failed', { error: String(e) });
    }
  }

  // --- OTP failure counter (per phone, across codes) --------------------------------------------

  /** Wrong codes entered for this phone in the current window. Fails open: the per-code limit in PostgreSQL still applies. */
  async otpFailures(phone: string): Promise<number> {
    try {
      return Number((await this.client.get(`otpfail:${phone}`)) ?? 0);
    } catch (e) {
      this.logger.warn('redis otpFailures failed', { error: String(e) });
      return 0;
    }
  }

  /** Counts one wrong code. The window starts at the first failure and is not extended by later ones. */
  async recordOtpFailure(phone: string, windowSeconds: number): Promise<number> {
    try {
      const key = `otpfail:${phone}`;
      const count = await this.client.incr(key);
      if (count === 1 || (await this.client.ttl(key)) < 0) await this.client.expire(key, windowSeconds);
      return count;
    } catch (e) {
      this.logger.warn('redis recordOtpFailure failed', { error: String(e) });
      return 0;
    }
  }

  async clearOtpFailures(phone: string): Promise<void> {
    try {
      await this.client.del(`otpfail:${phone}`);
    } catch (e) {
      this.logger.warn('redis clearOtpFailures failed', { error: String(e) });
    }
  }

  // --- Challenges --------------------------------------------------------------------------------

  async setChallenge(challengeHex: string, accountId: string, ttlSeconds: number): Promise<void> {
    try {
      await this.client.set(`challenge:${challengeHex}`, accountId, 'EX', ttlSeconds);
    } catch (e) {
      this.logger.warn('redis setChallenge failed', { error: String(e) });
    }
  }

  async consumeChallenge(challengeHex: string, accountId: string): Promise<boolean> {
    try {
      // Atomic get and delete
      const val = await this.client.getdel(`challenge:${challengeHex}`);
      return val === accountId;
    } catch {
      // Fallback if GETDEL not supported or error
      return false;
    }
  }

  // --- Blocklist ---------------------------------------------------------------------------------

  async addToBlocklist(walletIdHex: string): Promise<void> {
    try {
      await this.client.sadd('blocked_wallets', walletIdHex);
    } catch (e) {
      this.logger.warn('redis addToBlocklist failed', { error: String(e) });
    }
  }

  async flushDb(): Promise<void> {
    await this.client.flushdb();
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

