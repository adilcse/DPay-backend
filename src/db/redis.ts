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
  private readonly client: Redis;
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

  async touchSession(tokenHash: string, lastSeenAt: number, remainingTtlSeconds: number): Promise<void> {
    try {
      const session = await this.getSession(tokenHash);
      if (session) {
        session.lastSeenAt = lastSeenAt;
        await this.setSession(tokenHash, session, Math.max(60, remainingTtlSeconds));
      }
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

  async isWalletBlocked(walletIdHex: string): Promise<boolean> {
    try {
      const isMember = await this.client.sismember('blocked_wallets', walletIdHex);
      return isMember === 1;
    } catch {
      return false;
    }
  }

  async addToBlocklist(walletIdHex: string): Promise<void> {
    try {
      await this.client.sadd('blocked_wallets', walletIdHex);
    } catch (e) {
      this.logger.warn('redis addToBlocklist failed', { error: String(e) });
    }
  }

  async syncBlocklist(walletIdHexes: string[]): Promise<void> {
    try {
      if (walletIdHexes.length > 0) {
        await this.client.sadd('blocked_wallets', ...walletIdHexes);
      }
    } catch (e) {
      this.logger.warn('redis syncBlocklist failed', { error: String(e) });
    }
  }

  // --- Distributed Lock / Mutex ------------------------------------------------------------------

  async withLock<T>(resource: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
    const lockKey = `lock:${resource}`;
    const token = Math.random().toString(36).slice(2);
    let acquired = false;
    try {
      const res = await this.client.set(lockKey, token, 'PX', ttlMs, 'NX');
      acquired = res === 'OK';
    } catch {
      acquired = true; // graceful degradation if Redis unavailable
    }

    if (!acquired) {
      throw new Error(`could not acquire lock for ${resource}`);
    }

    try {
      return await fn();
    } finally {
      try {
        const current = await this.client.get(lockKey);
        if (current === token) {
          await this.client.del(lockKey);
        }
      } catch {
        // ignore unlock error
      }
    }
  }

  async flushDb(): Promise<void> {
    await this.client.flushdb();
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

