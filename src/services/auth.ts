import { createHash, createHmac, randomInt, timingSafeEqual } from 'node:crypto';
import { BankError, BankException } from '../domain/errors.ts';
import { Limits, PHONE_PATTERN } from '../domain/limits.ts';
import { maskPhone } from '../lib/logger.ts';
import type { AccountRow } from './accounts.ts';
import { toProfile, type Profile } from './accounts.ts';
import type { ServiceContext } from './context.ts';

export interface Session {
  readonly tokenHash: string;
  readonly phone: string;
  readonly deviceId: string;
  readonly expiresAt: number;
}

export interface OtpChallenge {
  phone: string;
  expiresAt: number;
  resendAvailableAt: number;
  /** Development only (EXPOSE_DEBUG_OTP). A production server never returns the code. */
  debugCode?: string;
}

export interface OtpResult {
  session: string;
  sessionExpiresAt: number;
  /** Null for a new user (go to ProfileSetup). */
  profile: Profile | null;
  /** The account is bound to another device (show MoveDeviceConfirm). */
  boundToOtherDevice: boolean;
}

interface OtpRow {
  phone: string;
  code_hash: string;
  expires_at: number;
  resend_at: number;
  attempts: number;
  window_start: number;
  sends_in_window: number;
}

const HOUR = 3600;

export const hashToken = (token: string): string => createHash('sha256').update(token, 'utf8').digest('hex');

function otpHash(ctx: ServiceContext, phone: string, code: string): Buffer {
  return createHmac('sha256', ctx.config.otpSecret).update(`${phone}:${code}`, 'utf8').digest();
}

export async function requestOtp(ctx: ServiceContext, phone: string): Promise<OtpChallenge> {
  if (!PHONE_PATTERN.test(phone)) throw new BankException(BankError.INVALID_PHONE);
  const now = ctx.clock();
  const code = randomInt(0, 1_000_000).toString().padStart(6, '0');

    const issued = await ctx.db.transaction(async () => {
      const existing = await ctx.db.get<OtpRow>('SELECT * FROM otps WHERE phone = ?', phone);
      if (existing && now < existing.resend_at) {
        throw new BankException(BankError.RESEND_TOO_SOON, 'wait before requesting another code', {
          resendAvailableAt: existing.resend_at,
        });
      }
      let windowStart = now;
      let sends = 1;
      if (existing && now - existing.window_start < HOUR) {
        if (existing.sends_in_window >= Limits.OTP_MAX_SENDS_PER_HOUR) {
          throw new BankException(BankError.RATE_LIMITED, 'too many codes requested, try again later', {
            retryAt: existing.window_start + HOUR,
          });
        }
        windowStart = existing.window_start;
        sends = existing.sends_in_window + 1;
      }
      const expiresAt = now + Limits.OTP_TTL_SECONDS;
      const resendAt = now + Limits.OTP_RESEND_SECONDS;
    const codeHashHex = otpHash(ctx, phone, code).toString('hex');

      await ctx.db.run(
        `INSERT INTO otps (phone, code_hash, expires_at, resend_at, attempts, window_start, sends_in_window)
       VALUES (?, ?, ?, ?, 0, ?, ?)
       ON CONFLICT(phone) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at,
         resend_at = excluded.resend_at, attempts = 0, window_start = excluded.window_start,
         sends_in_window = excluded.sends_in_window`,
        phone,
        codeHashHex,
        expiresAt,
        resendAt,
        windowStart,
        sends,
      );

      // Cache in Redis for ultra-fast checks
      await ctx.redis.setOtp(
        phone,
        {
          codeHash: codeHashHex,
          expiresAt,
          resendAt,
          attempts: 0,
          windowStart,
          sendsInWindow: sends,
        },
        Limits.OTP_TTL_SECONDS,
      );

      return { expiresAt, resendAt };
    });

    try {
      await ctx.sms.sendOtp(phone, code);
    } catch (e) {
      ctx.logger.error('otp delivery failed', { phone: maskPhone(phone), error: String(e) });
      await ctx.db.run('UPDATE otps SET resend_at = ? WHERE phone = ?', now, phone);
      throw new BankException(BankError.SERVICE_UNAVAILABLE, 'could not send the verification code');
    }

    return {
      phone,
      expiresAt: issued.expiresAt,
      resendAvailableAt: issued.resendAt,
      ...(ctx.config.exposeDebugOtp ? { debugCode: code } : {}),
    };
  }

    export async function verifyOtp(ctx: ServiceContext, phone: string, code: string, deviceId: string): Promise<OtpResult> {
      if (!PHONE_PATTERN.test(phone)) throw new BankException(BankError.INVALID_PHONE);
      const now = ctx.clock();

      // Failed attempts must be committed, so the transaction returns the failure instead of throwing.
        const outcome = await ctx.db.transaction(async (): Promise<BankError | OtpResult> => {
          const otp = await ctx.db.get<OtpRow>('SELECT * FROM otps WHERE phone = ?', phone);
          if (!otp) return BankError.OTP_EXPIRED;
          if (otp.attempts >= Limits.OTP_MAX_ATTEMPTS) return BankError.OTP_LOCKED;
          if (now > otp.expires_at) {
            await ctx.db.run('UPDATE otps SET code_hash = ?, expires_at = 0 WHERE phone = ?', '', phone);
            await ctx.redis.deleteOtp(phone);
            return BankError.OTP_EXPIRED;
          }
          const expected = Buffer.from(otp.code_hash, 'hex');
          const actual = otpHash(ctx, phone, code);
          if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
            const attempts = otp.attempts + 1;
            await ctx.db.run('UPDATE otps SET attempts = ? WHERE phone = ?', attempts, phone);
            return attempts >= Limits.OTP_MAX_ATTEMPTS ? BankError.OTP_LOCKED : BankError.INVALID_OTP;
          }
          // Keep the row (with a dead hash) so the resend / hourly limits still apply.
          await ctx.db.run('UPDATE otps SET code_hash = ?, expires_at = 0 WHERE phone = ?', '', phone);
          await ctx.redis.deleteOtp(phone);

          const token = ctx.random(32).toString('base64url');
          const tokenHash = hashToken(token);
          const expiresAt = now + ctx.config.sessionTtlSeconds;

            await ctx.db.run(
              'INSERT INTO sessions (token_hash, phone, device_id, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)',
              tokenHash,
              phone,
              deviceId,
              now,
              expiresAt,
              now,
            );

          // Cache session in Redis for sub-millisecond authentication
          await ctx.redis.setSession(
            tokenHash,
            { phone, deviceId, expiresAt, lastSeenAt: now },
            ctx.config.sessionTtlSeconds,
          );

          const account = await ctx.db.get<AccountRow>('SELECT * FROM accounts WHERE phone = ?', phone);
          return {
            session: token,
            sessionExpiresAt: expiresAt,
            profile: account ? toProfile(account) : null,
            boundToOtherDevice: !!account && account.bound_device_id !== null && account.bound_device_id !== deviceId,
          };
        });

        if (typeof outcome === 'string') throw new BankException(outcome);
        ctx.logger.info('otp verified', { phone: maskPhone(phone), newUser: outcome.profile === null });
        return outcome;
      }

        export async function authenticate(ctx: ServiceContext, token: string | undefined): Promise<Session> {
          if (!token) throw new BankException(BankError.NOT_AUTHENTICATED);
          const tokenHash = hashToken(token);
  const now = ctx.clock();

          // Check Redis cache first for sub-millisecond fast storage lookup
          const cached = await ctx.redis.getSession(tokenHash);
          if (cached) {
            if (cached.expiresAt <= now) {
              await ctx.redis.deleteSession(tokenHash);
              throw new BankException(BankError.NOT_AUTHENTICATED);
            }
            if (now - cached.lastSeenAt > 60) {
              const remainingTtl = cached.expiresAt - now;
              await ctx.redis.touchSession(tokenHash, now, remainingTtl);
              await ctx.db.run('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?', now, tokenHash);
            }
            return { tokenHash, phone: cached.phone, deviceId: cached.deviceId, expiresAt: cached.expiresAt };
          }

          // Cache miss: fall back to PostgreSQL
          const row = await ctx.db.get<{ phone: string; device_id: string; expires_at: number; last_seen_at: number }>(
            'SELECT phone, device_id, expires_at, last_seen_at FROM sessions WHERE token_hash = ?',
            tokenHash,
          );
          if (!row || row.expires_at <= now) throw new BankException(BankError.NOT_AUTHENTICATED);

          if (now - row.last_seen_at > 60) {
            await ctx.db.run('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?', now, tokenHash);
          }

          // Populate Redis cache
          const remainingTtl = Math.max(1, row.expires_at - now);
          await ctx.redis.setSession(
            tokenHash,
            { phone: row.phone, deviceId: row.device_id, expiresAt: row.expires_at, lastSeenAt: now },
            remainingTtl,
          );

          return { tokenHash, phone: row.phone, deviceId: row.device_id, expiresAt: row.expires_at };
        }

          export async function logout(ctx: ServiceContext, session: Session): Promise<void> {
            await ctx.redis.deleteSession(session.tokenHash);
            await ctx.db.run('DELETE FROM sessions WHERE token_hash = ?', session.tokenHash);
          }
