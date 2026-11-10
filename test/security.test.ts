// Regression tests for the security audit findings (B-02 … B-14).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { AndroidKeyAttestationVerifier, AttestationError } from '../src/attestation/verifier.ts';
import { planDenominations } from '../src/protocol/denominations.ts';
import { Payment, PaymentBody } from '../src/protocol/messages.ts';
import * as P256 from '../src/protocol/p256.ts';
import { SigningDomain } from '../src/protocol/p256.ts';
import { b64, createTestBank, paymentIdOf, TestClient } from './helpers.ts';

const ADMIN = { 'x-admin-key': 'test-admin-key-0123456789abcdef' };
const START = 25_000_00;
// A valid ₹500 denomination plan (the same one the API tests load).
const PLAN_500 = planDenominations(500_00, false);

function hasOpenssl(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** Builds small X.509 chains with the system openssl, for the attestation chain rules. */
class CertFactory {
  readonly dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpay-attest-'));
  private n = 0;

  private run(args: string[]): void {
    execFileSync('openssl', args, { cwd: this.dir, stdio: 'ignore' });
  }

  private key(name: string): void {
    this.run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`]);
  }

  root(name: string): void {
    this.key(name);
    fs.writeFileSync(
      path.join(this.dir, `${name}.cnf`),
      '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=' + name + '\n[v3]\nbasicConstraints=critical,CA:TRUE\n',
    );
    this.run(['req', '-x509', '-new', '-key', `${name}.key`, '-days', '30', '-config', `${name}.cnf`, '-out', `${name}.pem`]);
  }

  /** Issues `name`, signed by `issuer`, with the given extension lines. */
  issue(name: string, issuer: string, extensions: string[]): void {
    this.key(name);
    fs.writeFileSync(path.join(this.dir, `${name}.cnf`), '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=' + name + '\n');
    this.run(['req', '-new', '-key', `${name}.key`, '-config', `${name}.cnf`, '-out', `${name}.csr`]);
    fs.writeFileSync(path.join(this.dir, `${name}.ext`), extensions.join('\n') + '\n');
    const serial = (++this.n + 0x1000).toString(16);
    this.run([
      'x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`,
      '-set_serial', `0x${serial}`, '-days', '30', '-extfile', `${name}.ext`, '-out', `${name}.pem`,
    ]);
  }

  cert(name: string): X509Certificate {
    return new X509Certificate(fs.readFileSync(path.join(this.dir, `${name}.pem`)));
  }

  cleanup(): void {
    fs.rmSync(this.dir, { recursive: true, force: true });
  }
}

const KEY_DESCRIPTION = '1.3.6.1.4.1.11129.2.1.17=DER:3000';

describe('B-02 attestation chain rules', { skip: hasOpenssl() ? false : 'openssl not available' }, () => {
  async function verifyChain(f: CertFactory, names: string[]): Promise<string> {
    const verifier = new AndroidKeyAttestationVerifier({
      roots: [f.cert('root')],
      packageName: 'com.qbitlog.dpay',
      signingCertDigests: ['00'.repeat(32)],
      revocation: { isRevoked: async () => false },
    });
    const chain = names.map((n) => f.cert(n).raw);
    try {
      await verifier.verify({
        publicKey: P256.compress(f.cert(names[0]!).publicKey),
        chain,
        challenge: randomBytes(32),
        kind: 'identity',
      });
      return 'ACCEPTED';
    } catch (e) {
      assert.ok(e instanceof AttestationError, `unexpected error: ${e}`);
      return e.message;
    }
  }

  it('rejects a forged leaf signed by a genuine attested app key (not a CA)', async () => {
    const f = new CertFactory();
    try {
      f.root('root');
      f.issue('batch', 'root', ['basicConstraints=critical,CA:TRUE']);
      // A real, attested app key: chains to the root, but is an end-entity certificate.
      f.issue('appkey', 'batch', ['basicConstraints=critical,CA:FALSE', KEY_DESCRIPTION]);
      // The attacker signs a "leaf" with it, carrying whatever key description they like.
      f.issue('forged', 'appkey', [KEY_DESCRIPTION]);
      assert.match(await verifyChain(f, ['forged', 'appkey', 'batch', 'root']), /certificate 1 is not a CA/);
    } finally {
      f.cleanup();
    }
  });

  it('rejects an attestation certificate used as an issuer even if it claims to be a CA', async () => {
    const f = new CertFactory();
    try {
      f.root('root');
      f.issue('batch', 'root', ['basicConstraints=critical,CA:TRUE']);
      f.issue('appkey', 'batch', ['basicConstraints=critical,CA:TRUE', KEY_DESCRIPTION]);
      f.issue('forged', 'appkey', [KEY_DESCRIPTION]);
      assert.match(
        await verifyChain(f, ['forged', 'appkey', 'batch', 'root']),
        /certificate 1 is an attestation certificate, not a CA/,
      );
    } finally {
      f.cleanup();
    }
  });

  it('rejects a chain that does not end at a configured root', async () => {
    const f = new CertFactory();
    try {
      f.root('root');
      f.root('other');
      f.issue('batch', 'other', ['basicConstraints=critical,CA:TRUE']);
      f.issue('leaf', 'batch', [KEY_DESCRIPTION]);
      assert.match(await verifyChain(f, ['leaf', 'batch', 'other']), /does not end at a Google hardware attestation root/);
    } finally {
      f.cleanup();
    }
  });

  it('lets a well-formed chain through the chain rules (it then fails on the key description)', async () => {
    const f = new CertFactory();
    try {
      f.root('root');
      f.issue('batch', 'root', ['basicConstraints=critical,CA:TRUE']);
      f.issue('leaf', 'batch', ['keyUsage=digitalSignature']);
      assert.match(await verifyChain(f, ['leaf', 'batch', 'root']), /missing key description extension/);
    } finally {
      f.cleanup();
    }
  });
});

describe('B-03 OTP guessing', () => {
  it('locks the phone after 10 wrong codes, across resends', async () => {
    const bank = await createTestBank();
    const phone = '9876543210';
    const verify = (code: string) => bank.request('POST', '/v1/auth/otp/verify', { body: { phone, code, deviceId: 'device-aaaaaaaa' } });
    let last = '';
    for (let round = 0; round < 2; round++) {
      bank.advance(31);
      const otp = await bank.request('POST', '/v1/auth/otp', { body: { phone } });
      assert.equal(otp.status, 200);
      last = otp.body.debugCode;
      const wrong = last === '000000' ? '111111' : '000000';
      for (let i = 0; i < 5; i++) assert.equal((await verify(wrong)).status >= 400, true);
    }
    // Ten failures: no new code, and even the right code for a fresh one would be refused.
    bank.advance(31);
    const blocked = await bank.request('POST', '/v1/auth/otp', { body: { phone } });
    assert.equal(blocked.body.error.code, 'OTP_LOCKED');
    assert.equal((await verify(last)).body.error.code, 'OTP_LOCKED');

    // Another phone is unaffected.
    const other = new TestClient(bank, '9123456789');
    await other.login();
  });

  it('does not lose failed attempts when wrong guesses arrive concurrently', async () => {
    const bank = await createTestBank();
    const phone = '9876543210';
    const otp = await bank.request('POST', '/v1/auth/otp', { body: { phone } });
    const wrongs = Array.from({ length: 12 }, (_, i) => String(100000 + i)).filter((c) => c !== otp.body.debugCode);
    await Promise.all(
      wrongs.map((code) => bank.request('POST', '/v1/auth/otp/verify', { body: { phone, code, deviceId: 'device-aaaaaaaa' } })),
    );
    const row = await bank.ctx.db.get<{ attempts: number }>('SELECT attempts FROM otps WHERE phone = ?', phone);
    assert.equal(row!.attempts, 5); // every guess was counted, and counting stopped at the limit
    const right = await bank.request('POST', '/v1/auth/otp/verify', { body: { phone, code: otp.body.debugCode, deviceId: 'device-aaaaaaaa' } });
    assert.equal(right.body.error.code, 'OTP_LOCKED');
  });
});

describe('B-04 frozen accounts', () => {
  it('cannot load, withdraw, settle, edit the profile or move device', async () => {
    const bank = await createTestBank();
    const asha = new TestClient(bank, '9876543210');
    const ravi = new TestClient(bank, '9123456789');
    await asha.onboard('Asha Rao', 'asha');
    await ravi.onboard('Ravi Kumar', 'ravi');
    assert.equal((await ravi.load(PLAN_500)).status, 201);
    const payment = ravi.pay(asha.paymentRequest(), 10_00, [10_00]);

    const freeze = await bank.request('POST', `/v1/admin/accounts/${asha.phone}/freeze`, { headers: ADMIN });
    assert.equal(freeze.body.frozen, true);
    assert.equal((await asha.call('GET', '/v1/account')).body.error.code, 'NOT_AUTHENTICATED'); // signed out
    await asha.login();

    const frozen = async (method: string, route: string, body?: unknown) => {
      const res = await asha.call(method, route, body);
      assert.equal(res.body?.error?.code, 'WALLET_FROZEN', `${method} ${route} → ${JSON.stringify(res.body)}`);
    };
    await frozen('POST', '/v1/bank/load', { amountPaise: 1_000_00 });
    await frozen('POST', '/v1/bank/withdraw', { amountPaise: 1_00 });
    await frozen('POST', '/v1/settlement', { received: [{ payment: b64(payment), receivedAt: bank.ctx.clock() }], sent: [] });
    await frozen('PATCH', '/v1/profile', { fullName: 'Someone Else' });
    await frozen('POST', '/v1/wallet/lease');

    const phone2 = new TestClient(bank, asha.phone);
    await phone2.login();
    assert.equal((await phone2.call('POST', '/v1/device/move')).body.error.code, 'WALLET_FROZEN');

    const account = await bank.ctx.db.get<{ online_balance_paise: number }>('SELECT online_balance_paise FROM accounts WHERE phone = ?', asha.phone);
    assert.equal(Number(account!.online_balance_paise), START);

    // Unfreezing restores service; the honest counterparty's money was never at risk.
    await bank.request('POST', `/v1/admin/accounts/${asha.phone}/unfreeze`, { headers: ADMIN });
    const ok = await asha.call('POST', '/v1/settlement', { received: [{ payment: b64(payment), receivedAt: bank.ctx.clock() }], sent: [] });
    assert.equal(ok.body.creditedPaise, 10_00);
  });
});

describe('B-05 concurrent issuance', () => {
  it('cannot exceed the offline limit with parallel loads', async () => {
    const bank = await createTestBank();
    const asha = new TestClient(bank, '9876543210');
    await asha.onboard('Asha Rao', 'asha');
    const plan = planDenominations(3_000_00);
    const results = await Promise.all([asha.load(plan), asha.load(plan), asha.load(plan)]);
    assert.deepEqual(results.map((r) => r.status).sort(), [201, 422, 422]);
    for (const r of results.filter((x) => x.status !== 201)) assert.equal(r.body.error.code, 'LIMIT_EXCEEDED');

    const status = (await asha.call('GET', '/v1/wallet')).body;
    assert.equal(status.remainingLoadCapacityPaise, 2_000_00);
    assert.equal((await asha.call('GET', '/v1/account')).body.onlineBalancePaise, START - 3_000_00);
  });

  it('gives parallel lease refreshes distinct sequence numbers', async () => {
    const bank = await createTestBank();
    const asha = new TestClient(bank, '9876543210');
    await asha.onboard('Asha Rao', 'asha');
    await asha.load([1_00]);
    const leases = await Promise.all(Array.from({ length: 5 }, () => asha.call('POST', '/v1/wallet/lease')));
    const sequences = leases.map((l) => l.body.sequence).sort();
    assert.deepEqual(sequences, [2, 3, 4, 5, 6]);
  });
});

describe('B-08 sessions', () => {
  it('keeps at most five sessions per phone, dropping the oldest', async () => {
    const bank = await createTestBank();
    const tokens: string[] = [];
    for (let i = 0; i < 6; i++) {
      bank.advance(3600); // stay under the hourly OTP send limit
      const c = new TestClient(bank, '9876543210', 'device-aaaaaaaa');
      await c.login();
      tokens.push(c.token);
    }
    const status = await Promise.all(tokens.map((t) => bank.request('GET', '/v1/profile', { token: t })));
    assert.equal(status[0]!.body.error?.code, 'NOT_AUTHENTICATED');
    for (const s of status.slice(1)) assert.notEqual(s.body?.error?.code, 'NOT_AUTHENTICATED');
    const rows = await bank.ctx.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM sessions WHERE phone = ?', '9876543210');
    assert.equal(Number(rows!.n), 5);
  });

  it('only moves the account to a new device right after an OTP login', async () => {
    const bank = await createTestBank();
    const asha = new TestClient(bank, '9876543210');
    await asha.onboard('Asha Rao', 'asha');
    const phone2 = new TestClient(bank, asha.phone);
    await phone2.login();
    bank.advance(16 * 60); // e.g. a token stolen and used later
    const stale = await phone2.call('POST', '/v1/device/move');
    assert.equal(stale.status, 401);
    assert.equal(stale.body.error.code, 'NOT_AUTHENTICATED');
    assert.equal((await asha.refreshLease()).status, 200); // the real device is untouched

    await phone2.login();
    assert.equal((await phone2.call('POST', '/v1/device/move')).status, 204);
    assert.equal((await asha.refreshLease()).body.error.code, 'NOT_AUTHENTICATED');
  });
});

describe('B-09 payment id reuse', () => {
  it('records fraud and freezes a payer who signs two payments with one id', async () => {
    const bank = await createTestBank();
    const asha = new TestClient(bank, '9876543210');
    const ravi = new TestClient(bank, '9123456789');
    const meera = new TestClient(bank, '9000000009');
    await asha.onboard('Asha Rao', 'asha');
    await ravi.onboard('Ravi Kumar', 'ravi');
    await meera.onboard('Meera Shah', 'meera');
    assert.equal((await asha.load(PLAN_500)).status, 201);

    const first = asha.pay(ravi.paymentRequest(), 50_00, [50_00]);
    // Modified payer software: a second payment, to someone else, reusing the first payment's id.
    const request = meera.paymentRequest();
    const note = asha.notes.find((n) => n.value === 20_00)!;
    const body = PaymentBody.encode({
      paymentId: paymentIdOf(first),
      payerWalletId: asha.walletId,
      receiverWalletId: request.cert.walletId,
      receiverKey: request.cert.walletKey,
      challenge: request.challenge,
      amount: 20_00,
      createdAt: bank.ctx.clock(),
      noteIds: [note.noteId],
    });
    const second = Payment.encode({
      body,
      spends: [{ noteCertificate: note.cert, signature: P256.sign(note.privateKey!, SigningDomain.NOTE_SPEND, body) }],
      payerLease: asha.lease,
    });

    const one = await ravi.call('POST', '/v1/settlement', { received: [{ payment: b64(first), receivedAt: bank.ctx.clock() }] });
    assert.equal(one.body.creditedPaise, 50_00);
    const two = await meera.call('POST', '/v1/settlement', { received: [{ payment: b64(second), receivedAt: bank.ctx.clock() }] });
    assert.deepEqual(two.body.rejections.map((r: any) => r.code), ['PAYMENT_ID_CONFLICT']);
    // Uploading it again does not pile up events.
    await meera.call('POST', '/v1/settlement', { received: [{ payment: b64(second), receivedAt: bank.ctx.clock() }] });

    const events = (await bank.request('GET', '/v1/admin/fraud-events', { headers: ADMIN })).body.events;
    assert.deepEqual(events.map((e: any) => e.kind), ['PAYMENT_ID_REUSE']);
    assert.equal((await asha.refreshLease()).body.error.code, 'WALLET_FROZEN');
    assert.deepEqual((await meera.call('GET', '/v1/blocklist')).body.walletIds, [b64(asha.walletId)]);
  });

  it('ignores an unsigned body that merely names an existing payment id', async () => {
    const bank = await createTestBank();
    const asha = new TestClient(bank, '9876543210');
    const ravi = new TestClient(bank, '9123456789');
    await asha.onboard('Asha Rao', 'asha');
    await ravi.onboard('Ravi Kumar', 'ravi');
    assert.equal((await asha.load(PLAN_500)).status, 201);
    const first = asha.pay(ravi.paymentRequest(), 50_00, [50_00]);
    await ravi.call('POST', '/v1/settlement', { received: [{ payment: b64(first), receivedAt: bank.ctx.clock() }] });

    // Ravi tries to frame Asha: same id, different body, but he cannot produce her note signature.
    const decoded = Payment.decode(first);
    const original = PaymentBody.decode(decoded.body);
    const forgedBody = PaymentBody.encode({ ...original, amount: 49_00 });
    const forged = Payment.encode({ body: forgedBody, spends: decoded.spends, payerLease: decoded.payerLease });
    const res = await ravi.call('POST', '/v1/settlement', { received: [{ payment: b64(forged), receivedAt: bank.ctx.clock() }] });
    assert.deepEqual(res.body.rejections.map((r: any) => r.code), ['INVALID_PAYMENT']);
    assert.equal((await bank.request('GET', '/v1/admin/fraud-events', { headers: ADMIN })).body.events.length, 0);
    assert.equal((await asha.refreshLease()).status, 200);
  });
});

describe('B-11 / B-14 exposure', () => {
  it('does not serve API docs unless enabled', async () => {
    const bank = await createTestBank({ EXPOSE_API_DOCS: 'false' });
    for (const route of ['/docs', '/docs/openapi.json', '/docs/openapi.yaml', '/api-docs']) {
      assert.equal((await bank.request('GET', route)).status, 404, route);
    }
  });

  it('caps request bodies at 16 kB except on the authenticated bulk routes', async () => {
    const bank = await createTestBank();
    const big = 'x'.repeat(20 * 1024);
    const login = await bank.request('POST', '/v1/auth/otp', { body: { phone: '9876543210', padding: big } });
    assert.equal(login.status, 413);

    // The bulk routes take large bodies only from a signed-in caller.
    const anonymous = await bank.request('POST', '/v1/settlement', { body: { received: [], sent: [], padding: big } });
    assert.equal(anonymous.status, 401);
    const asha = new TestClient(bank, '9876543210');
    await asha.onboard('Asha Rao', 'asha');
    const signedIn = await asha.call('POST', '/v1/settlement', { received: [], sent: [], padding: big });
    assert.notEqual(signedIn.status, 413);
    assert.notEqual(signedIn.status, 401);
  });
});
