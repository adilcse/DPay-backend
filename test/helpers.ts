import { generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import http from 'node:http';
import { duplexPair } from 'node:stream';
import { after } from 'node:test';
import { createApp } from '../src/app.ts';
import { DisabledIntegrityVerifier } from '../src/attestation/playIntegrity.ts';
import { DisabledAttestationVerifier } from '../src/attestation/verifier.ts';
import { loadConfig } from '../src/config.ts';
import { Database } from '../src/db/database.ts';
import { RedisService } from '../src/db/redis.ts';
import { createLogger } from '../src/lib/logger.ts';
import { Issuer } from '../src/protocol/issuer.ts';
import { NoteCertificate, Payment, PaymentBody, WalletCertificate, WalletLease } from '../src/protocol/messages.ts';
import * as P256 from '../src/protocol/p256.ts';
import { SigningDomain } from '../src/protocol/p256.ts';
import type { ServiceContext } from '../src/services/context.ts';

export const T0 = 1_800_000_000;

export interface TestBank {
  ctx: ServiceContext;
  sms: Map<string, string>;
  setNow(t: number): void;
  advance(seconds: number): void;
  request(method: string, path: string, opts?: { body?: unknown; token?: string; headers?: Record<string, string> }): Promise<{ status: number; body: any }>;
  close(): Promise<void>;
}

  let sharedDb: Database | null = null;
  let sharedRedis: RedisService | null = null;

  after(async () => {
    if (sharedDb) {
      const db = sharedDb;
      sharedDb = null;
      await db.close();
    }
    if (sharedRedis) {
      const redis = sharedRedis;
      sharedRedis = null;
      await redis.close();
    }
  });

  export async function createTestBank(env: Record<string, string> = {}): Promise<TestBank> {
    let now = T0;
    const sms = new Map<string, string>();
    const config = loadConfig({
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      ADMIN_API_KEY: 'test-admin-key-0123456789abcdef',
      DATABASE_URL: process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/dpay_test_db',
      // Logical database 15, not 0: the suite calls FLUSHDB, which must never hit a development server's sessions.
      REDIS_URL: process.env.TEST_REDIS_URL ?? 'redis://localhost:6379/15',
      MOCK_BANK_AUTO_LOAD: 'false',
      ...env,
    });

    if (!sharedDb) {
      sharedDb = new Database(config.databaseUrl);
      await sharedDb.init();
    }
    await sharedDb.truncateAll();

    if (!sharedRedis) {
      sharedRedis = new RedisService(config.redisUrl, createLogger('silent'));
    }
    await sharedRedis.flushDb();

    const ctx: ServiceContext = {
      config,
      db: sharedDb,
      redis: sharedRedis,
      issuer: Issuer.demo(),
      attestation: new DisabledAttestationVerifier(),
      integrity: new DisabledIntegrityVerifier(),
      sms: { sendOtp: async (phone, code) => void sms.set(phone, code) },
      logger: createLogger('silent'),
      clock: () => now,
      random: (n) => randomBytes(n),
    };
    const server = http.createServer(createApp(ctx));

    const request: TestBank['request'] = (method, path, opts = {}) =>
      new Promise((resolve, reject) => {
        // In-memory connection: this sandbox (and CI) may not allow binding ports.
        const [client, serverSide] = duplexPair();
        Object.defineProperty(serverSide, 'remoteAddress', { value: '127.0.0.1' });
        server.emit('connection', serverSide);
        const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
        const req = http.request(
          {
            method,
            path,
            createConnection: () => client as any,
            headers: {
              ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
              ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
              ...opts.headers,
            },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
              const text = Buffer.concat(chunks).toString('utf8');
              let parsedBody: any = undefined;
              if (text) {
                try {
                  parsedBody = JSON.parse(text);
                } catch {
                  parsedBody = text;
                }
              }
              resolve({ status: res.statusCode!, body: parsedBody });
              client.destroy();
              serverSide.destroy();
            });
          },
        );
        req.on('error', (err) => {
          client.destroy();
          serverSide.destroy();
          reject(err);
        });
        if (payload) req.write(payload);
        req.end();
      });

    return {
      ctx,
      sms,
      setNow: (t) => void (now = t),
      advance: (s) => void (now += s),
      request,
      close: async () => {
        server.close();
      },
    };
  }

  export const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64');
  export const unb64 = (s: string): Buffer => Buffer.from(s, 'base64');

  function newKey(): { privateKey: KeyObject; publicKey: Buffer } {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return { privateKey, publicKey: P256.compress(publicKey) };
  }

  interface HeldNote {
    cert: Buffer;
    noteId: Buffer;
    value: number;
    privateKey: KeyObject | null;
  }

  /**
   * A software stand-in for the phone: identity key, single-use note keys, payment building.
   * `allowReuse` simulates compromised hardware that can sign with a note key twice.
   */
  export class TestClient {
    readonly phone: string;
    readonly deviceId: string;
    token = '';
    walletCertificate: Buffer = Buffer.alloc(0);
    walletId: Buffer = Buffer.alloc(0);
    lease: Buffer = Buffer.alloc(0);
    notes: HeldNote[] = [];
    private identity = newKey();
    private readonly bank: TestBank;

    constructor(bank: TestBank, phone: string, deviceId = `device-${randomBytes(6).toString('hex')}`) {
      this.bank = bank;
      this.phone = phone;
      this.deviceId = deviceId;
    }

    call(method: string, path: string, body?: unknown) {
      return this.bank.request(method, path, { body, token: this.token });
    }

    async login(): Promise<any> {
      this.bank.advance(31); // OTP resend window
      const otp = await this.bank.request('POST', '/v1/auth/otp', { body: { phone: this.phone } });
      if (otp.status !== 200) throw new Error(`otp: ${JSON.stringify(otp.body)}`);
      const verified = await this.bank.request('POST', '/v1/auth/otp/verify', {
        body: { phone: this.phone, code: otp.body.debugCode, deviceId: this.deviceId },
      });
      if (verified.status !== 200) throw new Error(`verify: ${JSON.stringify(verified.body)}`);
      this.token = verified.body.session;
      return verified.body;
    }

    async onboard(fullName: string, handle: string): Promise<void> {
      await this.login();
      const reg = await this.call('POST', '/v1/profile', { fullName, handle, email: null });
      if (reg.status !== 201) throw new Error(`register: ${JSON.stringify(reg.body)}`);
      await this.provision();
    }

    async provision(): Promise<{ status: number; body: any }> {
      this.identity = newKey();
      const ch = await this.call('POST', '/v1/provisioning/challenge');
      if (ch.status !== 200) return ch;
      const res = await this.call('POST', '/v1/wallet/certificate', {
        challenge: ch.body.challenge,
        identity: { publicKey: b64(this.identity.publicKey), attestationChain: [] },
      });
      if (res.status === 201) {
        this.walletCertificate = unb64(res.body.walletCertificate);
        this.walletId = unb64(res.body.walletId);
        this.notes = [];
      }
      return res;
    }

    async load(values: number[]): Promise<{ status: number; body: any }> {
      const ch = await this.call('POST', '/v1/provisioning/challenge');
      if (ch.status !== 200) return ch;
      const keys = values.map(() => newKey());
      const res = await this.call('POST', '/v1/wallet/notes', {
        challenge: ch.body.challenge,
        values,
        keys: keys.map((k) => ({ publicKey: b64(k.publicKey), attestationChain: [] })),
      });
      if (res.status === 201) {
        res.body.noteCertificates.forEach((c: string) => {
          const cert = NoteCertificate.decodeAndVerify(unb64(c), this.bank.ctx.issuer.trustAnchors);
          const key = keys.find((k) => k.publicKey.equals(cert.noteKey))!;
          this.notes.push({ cert: unb64(c), noteId: cert.noteId, value: cert.value, privateKey: key.privateKey });
        });
        this.installLease(res.body);
      }
      return res;
    }

    async refreshLease(): Promise<{ status: number; body: any }> {
      const res = await this.call('POST', '/v1/wallet/lease');
      if (res.status === 200) this.installLease(res.body);
      return res;
    }

    private installLease(body: { lease: string; outstandingNoteIds: string[] }) {
      const lease = WalletLease.decodeAndVerify(unb64(body.lease), this.bank.ctx.issuer.trustAnchors);
      const digest = WalletLease.ledgerDigest(body.outstandingNoteIds.map(unb64));
      if (!digest.equals(lease.ledgerDigest)) throw new Error('lease digest mismatch');
      if (!lease.walletId.equals(this.walletId)) throw new Error('lease for another wallet');
      this.lease = unb64(body.lease);
    }

    /** Receiver side: a fresh challenge for a payment request. */
    paymentRequest(): { cert: WalletCertificate; challenge: Buffer } {
      return {
        cert: WalletCertificate.decodeAndVerify(this.walletCertificate, this.bank.ctx.issuer.trustAnchors, this.bank.ctx.clock()),
        challenge: randomBytes(16),
      };
    }

    /** Payer side: sign a payment with the notes of the given values. */
    pay(request: { cert: WalletCertificate; challenge: Buffer }, amount: number, noteValues: number[], opts: { allowReuse?: boolean } = {}): Buffer {
      const chosen: HeldNote[] = [];
      for (const v of noteValues) {
        const note = this.notes.find((n) => n.value === v && !chosen.includes(n) && (n.privateKey || opts.allowReuse));
        if (!note) throw new Error(`no note of ${v}`);
        chosen.push(note);
      }
      const body = PaymentBody.encode({
        paymentId: randomBytes(16),
        payerWalletId: this.walletId,
        receiverWalletId: request.cert.walletId,
        receiverKey: request.cert.walletKey,
        challenge: request.challenge,
        amount,
        createdAt: this.bank.ctx.clock(),
        noteIds: chosen.map((n) => n.noteId),
      });
      const spends = chosen.map((n) => {
        const key = n.privateKey ?? (n as any).spentKey;
        const signature = P256.sign(key, SigningDomain.NOTE_SPEND, body);
        (n as any).spentKey = key;
        n.privateKey = null; // single use
        return { noteCertificate: n.cert, signature };
      });
      return Payment.encode({ body, spends, payerLease: this.lease });
    }
  }

  export function paymentIdOf(payment: Buffer): Buffer {
    return PaymentBody.decode(Payment.decode(payment).body).paymentId;
  }
