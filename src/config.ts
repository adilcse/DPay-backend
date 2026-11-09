import { z } from 'zod';

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

const csv = z
  .string()
  .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean));

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(0).max(65535).default(8080),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error', 'silent']).default('info'),
  TRUST_PROXY: z.string().optional(),
  CORS_ORIGINS: csv.optional(),

  DATABASE_URL: z.string().optional(),
  DB_USER: z.string().optional(),
  DB_PASSWORD: z.string().optional(),
  DATABASE: z.string().optional(),
  DB_HOST: z.string().optional(),
  DB_PORT: z.coerce.number().int().optional(),

  DATABASE_PATH: z.string().default('./data/dpay.db'),
  REDIS_URL: z.string().optional(),
  REDIS_HOST: z.string().optional(),
  REDIS_PORT: z.coerce.number().int().optional(),

  MOCK_BANK_NAME: z.string().default('DPay Reserve Bank'),
  MOCK_BANK_IFSC: z.string().default('DPAY0000001'),
  MOCK_BANK_INFINITE_MONEY: bool.default(true),
  MOCK_BANK_AUTO_LOAD: bool.default(true),

  /** PKCS#8 PEM file with the issuer's P-256 private key (production: an HSM-backed signer). */
  ISSUER_KEY_FILE: z.string().optional(),
  ISSUER_KEY_ID: z.coerce.number().int().min(1).default(1),

  /** HMAC key for OTP hashes (≥ 32 chars). */
  OTP_SECRET: z.string().min(32).optional(),
  /** Return the OTP in the response (`debugCode`), like the app's FakeBank. Never in production. */
  EXPOSE_DEBUG_OTP: bool.optional(),
  SMS_PROVIDER: z.enum(['console', 'webhook', 'whatsapp']).optional(),
  SMS_WEBHOOK_URL: z.url().optional(),
  SMS_WEBHOOK_TOKEN: z.string().optional(),

  WHATSAPP_ACCESS_TOKEN: z.string().optional(),
  WHATSAPP_PHONE_NUMBER_ID: z.string().optional(),
  WHATSAPP_BUSINESS_ACCOUNT_ID: z.string().optional(),
  WHATSAPP_API_VERSION: z.string().default('v22.0'),
  WHATSAPP_OTP_TEMPLATE: z.string().default('app_otp'),
  WHATSAPP_NOTIFY_NUMBER: z.string().optional(),
  WHATSAPP_REQUEST_TIMEOUT_MS: z.coerce.number().int().default(10000),

  SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  /** Demo online balance credited to new accounts (paise). Default ₹25,000 outside production. */
  STARTING_BALANCE_PAISE: z.coerce.number().int().min(0).optional(),

  ATTESTATION_MODE: z.enum(['off', 'enforce']).optional(),
  ATTESTATION_ROOTS_FILE: z.string().optional(),
  ANDROID_PACKAGE_NAME: z.string().default('com.qbitlog.dpay'),
  ANDROID_SIGNING_CERT_DIGESTS: csv.optional(),
  PLAY_INTEGRITY_MODE: z.enum(['off', 'enforce']).default('off'),
  PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE: z.string().optional(),

  /** Offline limit for wallets without hardware-enforced single use or strong integrity (paise). */
  REDUCED_OFFLINE_LIMIT_PAISE: z.coerce.number().int().min(100).default(1_000_00),
  NOTE_LIFETIME_DAYS: z.coerce.number().int().min(5).max(30).default(14),
  SETTLEMENT_GRACE_DAYS: z.coerce.number().int().min(1).max(90).default(7),
  /** Credit receivers of a proven double spend (the bank absorbs the loss). */
  GUARANTEE_OFFLINE_PAYMENTS: bool.default(false),

  ADMIN_API_KEY: z.string().min(24).optional(),
  MAINTENANCE_INTERVAL_SECONDS: z.coerce.number().int().min(10).default(300),
});

export interface Config {
  readonly env: 'development' | 'test' | 'production';
  readonly host: string;
  readonly port: number;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error' | 'silent';
  readonly trustProxy: string | undefined;
  readonly corsOrigins: readonly string[] | undefined;
  readonly databaseUrl: string;
  readonly databasePath: string;
  readonly redisUrl: string;
  readonly mockBank: {
    readonly infiniteMoney: boolean;
    readonly autoLoad: boolean;
    readonly name: string;
    readonly ifsc: string;
  };
  readonly issuerKeyFile: string | undefined;
  readonly issuerKeyId: number;
  readonly otpSecret: string;
  readonly exposeDebugOtp: boolean;
  readonly sms: {
    readonly provider: 'console' | 'webhook' | 'whatsapp';
    readonly webhookUrl: string | undefined;
    readonly webhookToken: string | undefined;
    readonly whatsapp?: {
      readonly accessToken: string;
      readonly phoneNumberId: string;
      readonly businessAccountId?: string;
      readonly apiVersion: string;
      readonly otpTemplate: string;
      readonly notifyNumber?: string;
      readonly timeoutMs: number;
    };
  };
  readonly sessionTtlSeconds: number;
  readonly startingBalancePaise: number;
  readonly attestation: {
    mode: 'off' | 'enforce';
    rootsFile: string | undefined;
    packageName: string;
    signingCertDigests: readonly string[];
  };
  readonly playIntegrity: { mode: 'off' | 'enforce'; serviceAccountFile: string | undefined };
  readonly reducedOfflineLimitPaise: number;
  readonly noteLifetimeSeconds: number;
  readonly settlementGraceSeconds: number;
  readonly guaranteeOfflinePayments: boolean;
  readonly adminApiKey: string | undefined;
  readonly maintenanceIntervalSeconds: number;
}

const DAY = 86_400;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new Error(`invalid configuration:\n${z.prettifyError(parsed.error)}`);
  }
  const e = parsed.data;
  const production = e.NODE_ENV === 'production';

  let databaseUrl = e.DATABASE_URL;
  if (!databaseUrl && (e.DB_HOST || e.DATABASE || e.DB_USER)) {
    const user = e.DB_USER ?? 'postgres';
    const pass = e.DB_PASSWORD ? `:${e.DB_PASSWORD}` : '';
    const host = e.DB_HOST ?? 'localhost';
    const port = e.DB_PORT ?? 5432;
    const db = e.DATABASE ?? (e.NODE_ENV === 'test' ? 'dpay_test_db' : 'dpay');
    databaseUrl = `postgres://${user}${pass}@${host}:${port}/${db}`;
  }
  if (!databaseUrl) {
    databaseUrl = e.NODE_ENV === 'test' ? 'postgres://postgres:postgres@localhost:5432/dpay_test_db' : 'postgres://postgres:postgres@localhost:5432/dpay';
  }

  let redisUrl = e.REDIS_URL;
  if (!redisUrl) {
    const rHost = e.REDIS_HOST ?? 'localhost';
    const rPort = e.REDIS_PORT ?? 6379;
    redisUrl = `redis://${rHost}:${rPort}`;
  }

  const config: Config = {
    env: e.NODE_ENV,
    host: e.HOST,
    port: e.PORT,
    logLevel: e.LOG_LEVEL,
    trustProxy: e.TRUST_PROXY,
    corsOrigins: e.CORS_ORIGINS,
    databaseUrl,
    databasePath: e.DATABASE_PATH,
    redisUrl,
    mockBank: {
      infiniteMoney: e.MOCK_BANK_INFINITE_MONEY,
      autoLoad: e.MOCK_BANK_AUTO_LOAD,
      name: e.MOCK_BANK_NAME,
      ifsc: e.MOCK_BANK_IFSC,
    },
    issuerKeyFile: e.ISSUER_KEY_FILE,
    issuerKeyId: e.ISSUER_KEY_ID,
    otpSecret: e.OTP_SECRET ?? (production ? '' : 'dev-only-otp-secret-not-for-production-use'),
    exposeDebugOtp: e.EXPOSE_DEBUG_OTP ?? !production,
    sms: {
      provider: e.SMS_PROVIDER ?? (e.WHATSAPP_ACCESS_TOKEN && e.WHATSAPP_PHONE_NUMBER_ID ? 'whatsapp' : 'console'),
      webhookUrl: e.SMS_WEBHOOK_URL,
      webhookToken: e.SMS_WEBHOOK_TOKEN,
      whatsapp: {
        accessToken: e.WHATSAPP_ACCESS_TOKEN ?? '',
        phoneNumberId: e.WHATSAPP_PHONE_NUMBER_ID ?? '',
        businessAccountId: e.WHATSAPP_BUSINESS_ACCOUNT_ID,
        apiVersion: e.WHATSAPP_API_VERSION,
        otpTemplate: e.WHATSAPP_OTP_TEMPLATE,
        notifyNumber: e.WHATSAPP_NOTIFY_NUMBER,
        timeoutMs: e.WHATSAPP_REQUEST_TIMEOUT_MS,
      },
    },
    sessionTtlSeconds: e.SESSION_TTL_DAYS * DAY,
    startingBalancePaise: e.STARTING_BALANCE_PAISE ?? (production ? 0 : 25_000_00),
    attestation: {
      mode: e.ATTESTATION_MODE ?? (production ? 'enforce' : 'off'),
      rootsFile: e.ATTESTATION_ROOTS_FILE,
      packageName: e.ANDROID_PACKAGE_NAME,
      signingCertDigests: (e.ANDROID_SIGNING_CERT_DIGESTS ?? []).map((d) => d.toLowerCase().replace(/:/g, '')),
    },
    playIntegrity: { mode: e.PLAY_INTEGRITY_MODE, serviceAccountFile: e.PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE },
    reducedOfflineLimitPaise: e.REDUCED_OFFLINE_LIMIT_PAISE,
    noteLifetimeSeconds: e.NOTE_LIFETIME_DAYS * DAY,
    settlementGraceSeconds: e.SETTLEMENT_GRACE_DAYS * DAY,
    guaranteeOfflinePayments: e.GUARANTEE_OFFLINE_PAYMENTS,
    adminApiKey: e.ADMIN_API_KEY,
    maintenanceIntervalSeconds: e.MAINTENANCE_INTERVAL_SECONDS,
  };

  const problems: string[] = [];
  if (config.attestation.mode === 'enforce') {
    if (!config.attestation.rootsFile) problems.push('ATTESTATION_ROOTS_FILE is required when ATTESTATION_MODE=enforce');
    if (config.attestation.signingCertDigests.length === 0) {
      problems.push('ANDROID_SIGNING_CERT_DIGESTS is required when ATTESTATION_MODE=enforce');
    }
  }
  if (config.playIntegrity.mode === 'enforce' && !config.playIntegrity.serviceAccountFile) {
    problems.push('PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE is required when PLAY_INTEGRITY_MODE=enforce');
  }
  if (config.sms.provider === 'webhook' && !config.sms.webhookUrl) problems.push('SMS_WEBHOOK_URL is required for SMS_PROVIDER=webhook');
  if (config.sms.provider === 'whatsapp' && (!config.sms.whatsapp?.accessToken || !config.sms.whatsapp?.phoneNumberId)) {
    problems.push('WHATSAPP_ACCESS_TOKEN and WHATSAPP_PHONE_NUMBER_ID are required for SMS_PROVIDER=whatsapp');
  }
  if (production) {
    if (!config.issuerKeyFile) problems.push('ISSUER_KEY_FILE is required in production (the demo issuer key is public)');
    if (!e.OTP_SECRET) problems.push('OTP_SECRET is required in production');
    if (config.exposeDebugOtp) problems.push('EXPOSE_DEBUG_OTP must be false in production');
    if (config.attestation.mode !== 'enforce') problems.push('ATTESTATION_MODE must be enforce in production');
    if (config.sms.provider === 'console') problems.push('SMS_PROVIDER=console cannot deliver OTPs in production');
  }
  if (problems.length > 0) throw new Error(`invalid configuration:\n - ${problems.join('\n - ')}`);
  return config;
}
