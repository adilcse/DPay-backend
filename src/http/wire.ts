import { z } from 'zod';
import { BankError, BankException } from '../domain/errors.ts';

/**
 * Wire format: JSON, binary fields as standard padded base64 (`java.util.Base64.getEncoder()`),
 * money as integer paise, times as epoch seconds.
 */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function base64Bytes(opts: { size?: number; max?: number } = {}) {
  const maxChars = Math.ceil((opts.max ?? opts.size ?? 64 * 1024) / 3) * 4;
  return z
    .string()
    .max(maxChars)
    .regex(BASE64, 'must be standard base64')
    .transform((s, ctx) => {
      const bytes = Buffer.from(s, 'base64');
      if (opts.size !== undefined && bytes.length !== opts.size) {
        ctx.addIssue({ code: 'custom', message: `must decode to ${opts.size} bytes` });
        return z.NEVER;
      }
      return bytes;
    });
}

/** Recursively converts Buffers / Uint8Arrays to base64 strings for JSON responses. */
export function toWire(value: unknown): unknown {
  if (value instanceof Uint8Array) return Buffer.from(value).toString('base64');
  if (Array.isArray(value)) return value.map(toWire);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toWire(v)]));
  }
  return value;
}

export function parse<T extends z.ZodType>(schema: T, input: unknown): z.output<T> {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new BankException(BankError.INVALID_REQUEST, 'request validation failed', {
      issues: result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    });
  }
  return result.data;
}

/** Accepts "9876543210", "+919876543210" or "+91 98765 43210". */
export const phoneSchema = z.string().max(20).transform((s) => s.replace(/[\s-]/g, '').replace(/^\+91/, ''));

export const deviceIdSchema = z.string().regex(/^[A-Za-z0-9._:-]{8,128}$/, 'deviceId must be 8–128 URL-safe characters');

export const emailSchema = z
  .union([z.literal(''), z.email().max(254)])
  .nullish()
  .transform((v) => (v ? v.trim() : null));

export const fullNameSchema = z.string().trim().min(1).max(100);

export const keyAttestationSchema = z.object({
  /** Client-side Keystore alias; ignored by the server. */
  alias: z.string().max(128).optional(),
  publicKey: base64Bytes({ size: 33 }),
  attestationChain: z.array(base64Bytes({ max: 16 * 1024 })).max(10),
});
