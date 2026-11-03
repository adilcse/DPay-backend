import type { ServiceContext } from './context.ts';
import { refundExpiredNotes } from './wallets.ts';

/** Periodic housekeeping: expiry refunds and purging dead OTPs, challenges and sessions. */
  export async function runMaintenance(ctx: ServiceContext): Promise<{ refundedPaise: number }> {
    const now = ctx.clock();
    const refundedPaise = await ctx.db.transaction(async () => await refundExpiredNotes(ctx, now));
    await ctx.db.run('DELETE FROM sessions WHERE expires_at <= ?', now);
    await ctx.db.run('DELETE FROM challenges WHERE expires_at < ?', now);
    await ctx.db.run('DELETE FROM otps WHERE expires_at < ? AND window_start < ?', now, now - 3600);
    if (refundedPaise > 0) ctx.logger.info('expired notes refunded', { refundedPaise });
    return { refundedPaise };
  }
