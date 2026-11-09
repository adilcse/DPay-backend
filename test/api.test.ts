import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { planDenominations } from '../src/protocol/denominations.ts';
import { b64, createTestBank, paymentIdOf, T0, TestClient, type TestBank } from './helpers.ts';

const START = 25_000_00; // demo opening balance
const DAY = 86_400;

async function balance(c: TestClient): Promise<number> {
  return (await c.call('GET', '/v1/account')).body.onlineBalancePaise;
}

describe('auth & profile', () => {
  let bank: TestBank;
    beforeEach(async () => {
      bank = await createTestBank();
    });

    it('runs OTP login, registration and profile updates', async () => {
      const asha = new TestClient(bank, '9876543210');
      const first = await asha.login();
      assert.equal(first.profile, null);
      assert.equal(first.boundToOtherDevice, false);

      const avail = await bank.request('GET', '/v1/handles/availability?handle=asha.rao');
      assert.deepEqual(avail.body, { handle: 'asha.rao', available: true });
      const suggestion = await bank.request('GET', '/v1/handles/suggestion?fullName=Asha%20Rao');
      assert.equal(suggestion.body.suggestion, 'asha.rao@dpay');

      const reg = await asha.call('POST', '/v1/profile', { fullName: 'Asha Rao', handle: 'asha.rao', email: 'asha@example.com' });
      assert.equal(reg.status, 201);
      assert.deepEqual(reg.body, { phone: '9876543210', fullName: 'Asha Rao', handle: 'asha.rao@dpay', email: 'asha@example.com' });
      assert.equal((await asha.call('POST', '/v1/profile', { fullName: 'X', handle: 'other' })).body.error.code, 'ACCOUNT_EXISTS');

      assert.equal((await bank.request('GET', '/v1/handles/availability?handle=asha.rao@dpay')).body.available, false);
      const ravi = new TestClient(bank, '9123456789');
      await ravi.login();
      assert.equal((await ravi.call('POST', '/v1/profile', { fullName: 'Ravi', handle: 'asha.rao' })).body.error.code, 'HANDLE_TAKEN');
      assert.equal((await ravi.call('POST', '/v1/profile', { fullName: 'Ravi', handle: 'admin' })).body.error.code, 'HANDLE_TAKEN');
      assert.equal((await ravi.call('POST', '/v1/profile', { fullName: 'Ravi', handle: 'r..x' })).body.error.code, 'INVALID_HANDLE');

      const upd = await asha.call('PATCH', '/v1/profile', { fullName: 'Asha K Rao', email: '' });
      assert.equal(upd.body.fullName, 'Asha K Rao');
      assert.equal(upd.body.email, null);
      assert.equal(await balance(asha), START);

      const again = await new TestClient(bank, '9876543210', asha.deviceId).login();
      assert.equal(again.profile.handle, 'asha.rao@dpay');

      assert.equal((await asha.call('POST', '/v1/auth/logout')).status, 204);
      assert.equal((await asha.call('GET', '/v1/profile')).body.error.code, 'NOT_AUTHENTICATED');
    });

    it('enforces OTP rules', async () => {
      assert.equal((await bank.request('POST', '/v1/auth/otp', { body: { phone: '12345' } })).body.error.code, 'INVALID_PHONE');
      const otp = await bank.request('POST', '/v1/auth/otp', { body: { phone: '+91 98765 43210' } });
      assert.equal(otp.status, 200);
      assert.equal(otp.body.phone, '9876543210');
      assert.equal((await bank.request('POST', '/v1/auth/otp', { body: { phone: '9876543210' } })).body.error.code, 'RESEND_TOO_SOON');

      const wrong = otp.body.debugCode === '000000' ? '111111' : '000000';
      const verify = (code: string) =>
        bank.request('POST', '/v1/auth/otp/verify', { body: { phone: '9876543210', code, deviceId: 'device-aaaaaaaa' } });
      for (let i = 0; i < 4; i++) assert.equal((await verify(wrong)).body.error.code, 'INVALID_OTP');
      assert.equal((await verify(wrong)).body.error.code, 'OTP_LOCKED');
      assert.equal((await verify(otp.body.debugCode)).body.error.code, 'OTP_LOCKED');

      bank.advance(31);
      const next = await bank.request('POST', '/v1/auth/otp', { body: { phone: '9876543210' } });
      bank.advance(301);
      assert.equal((await verify(next.body.debugCode)).body.error.code, 'OTP_EXPIRED');
    });

    it('never returns the OTP when debug codes are off', async () => {
      const quiet = await createTestBank({ EXPOSE_DEBUG_OTP: 'false' });
      const otp = await quiet.request('POST', '/v1/auth/otp', { body: { phone: '9876543210' } });
      assert.equal(otp.body.debugCode, undefined);
      assert.equal(quiet.sms.get('9876543210')?.length, 6);
    });

    it('accepts requests with X-Forwarded-For header without throwing rate limit error', async () => {
      const res = await bank.request('POST', '/v1/auth/otp', {
        body: { phone: '9123456789' },
        headers: { 'x-forwarded-for': '10.0.2.2, 127.0.0.1' },
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.phone, '9123456789');
    });
  });

  describe('wallet, notes & leases', () => {
    let bank: TestBank;
    let asha: TestClient;
    beforeEach(async () => {
      bank = await createTestBank();
      asha = new TestClient(bank, '9876543210');
      await asha.onboard('Asha Rao', 'asha');
    });

    it('issues notes for the exact plan, debits first and covers them with a lease', async () => {
      const values = [200_00, 100_00, 90_00, 50_00, 20_00, 20_00, 10_00, 5_00, 2_00, 2_00, 1_00];
      const res = await asha.load(values);
      assert.equal(res.status, 201);
      assert.equal(res.body.noteCertificates.length, 11);
      assert.equal(res.body.sequence, 1);
      assert.equal(res.body.notAfter - res.body.issuedAt, 5 * DAY);
      assert.equal(res.body.outstandingValuePaise, 500_00);
      assert.equal(await balance(asha), START - 500_00);

      const status = (await asha.call('GET', '/v1/wallet')).body;
      assert.equal(status.provisioned, true);
      assert.equal(status.displayName, 'asha@dpay');
      assert.equal(status.remainingLoadCapacityPaise, 4_500_00);
      assert.equal(status.notes.length, 11);

      const lease = await asha.refreshLease();
      assert.equal(lease.body.sequence, 2);
      assert.equal(lease.body.outstandingNoteIds.length, 11);
    });

    it('accepts change-heavy plans used by the Android client', async () => {
      // Android client defaults to changeHeavy = true (12 notes for ₹500)
      const changeHeavy = planDenominations(500_00, true);
      assert.equal(changeHeavy.length, 12);
      const res = await asha.load(changeHeavy);
      assert.equal(res.status, 201);
      assert.equal(res.body.noteCertificates.length, 12);
    });

    it('rejects wrong denominations, the ₹5,000 cap and insufficient balance', async () => {
      assert.equal((await asha.load([300_00, 200_00])).body.error.code, 'INVALID_DENOMINATIONS');
      assert.equal((await asha.load([1_50])).body.error.code, 'INVALID_DENOMINATIONS');

      const full = planDenominations(5_000_00);
      assert.equal((await asha.load(full)).status, 201);
      const more = await asha.load([1_00]);
      assert.equal(more.body.error.code, 'LIMIT_EXCEEDED');
      assert.equal(more.body.error.details.remainingPaise, 0);

      const poor = await createTestBank({ STARTING_BALANCE_PAISE: '100' });
      const p = new TestClient(poor, '9000000001');
      await p.onboard('Poor', 'poor');
      assert.equal((await p.load([2_00, 1_00])).body.error.code, 'INSUFFICIENT_BALANCE');
    });

    it('makes challenges single use and short lived', async () => {
      const key = { publicKey: b64(Buffer.from('036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 'hex')), attestationChain: [] };
      const ch = await asha.call('POST', '/v1/provisioning/challenge');
      const notes = (challenge: string) => asha.call('POST', '/v1/wallet/notes', { challenge, values: [1_00], keys: [key] });
      assert.equal((await notes(ch.body.challenge)).status, 201);
      assert.equal((await notes(ch.body.challenge)).body.error.code, 'INVALID_CHALLENGE');

      const offCurve = await asha.call('POST', '/v1/wallet/notes', {
        challenge: (await asha.call('POST', '/v1/provisioning/challenge')).body.challenge,
        values: [1_00],
        keys: [{ publicKey: b64(Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 0xff)])), attestationChain: [] }],
      });
      assert.equal(offCurve.body.error.code, 'INVALID_REQUEST');

      const stale = await asha.call('POST', '/v1/provisioning/challenge');
      bank.advance(11 * 60);
      assert.equal((await notes(stale.body.challenge)).body.error.code, 'INVALID_CHALLENGE');
    });

    it('moves the account to a new device and stops leases for the old one', async () => {
      await asha.load([1_00]);
      const phone2 = new TestClient(bank, asha.phone);
      const login = await phone2.login();
      assert.equal(login.boundToOtherDevice, true);
      assert.equal((await phone2.provision()).body.error.code, 'DEVICE_MOVED');

      assert.equal((await phone2.call('POST', '/v1/device/move')).status, 204);
      assert.equal((await asha.refreshLease()).body.error.code, 'NOT_AUTHENTICATED'); // old sessions revoked
      assert.equal((await phone2.refreshLease()).body.error.code, 'WALLET_NOT_PROVISIONED');
      assert.equal((await phone2.provision()).status, 201);
      assert.equal((await phone2.refreshLease()).body.sequence, 1);

      // Old device logs in again: it's no longer the bound device.
      const old = new TestClient(bank, asha.phone, asha.deviceId);
      assert.equal((await old.login()).boundToOtherDevice, true);
      assert.equal((await old.refreshLease()).body.error.code, 'DEVICE_MOVED');
    });

    it('refunds notes that expire unspent after the grace period', async () => {
      await asha.load([2_00, 1_00]);
      bank.advance(14 * DAY + 1);
      assert.equal(await balance(asha), START - 3_00); // expired, still within grace
      assert.equal((await asha.refreshLease()).body.outstandingNoteIds.length, 0);
      bank.advance(7 * DAY);
      assert.equal(await balance(asha), START);
      const tx = (await asha.call('GET', '/v1/transactions')).body.entries;
      assert.deepEqual(
        tx.map((e: any) => e.kind),
        ['NOTE_EXPIRY_REFUND', 'NOTE_EXPIRY_REFUND', 'OFFLINE_LOAD', 'OPENING_CREDIT'],
      );
    });
  });

  describe('offline payments & settlement', () => {
    let bank: TestBank;
    let asha: TestClient;
    let ravi: TestClient;
    beforeEach(async () => {
      bank = await createTestBank();
      asha = new TestClient(bank, '9876543210');
      ravi = new TestClient(bank, '9123456789');
      await asha.onboard('Asha Rao', 'asha');
      await ravi.onboard('Ravi Kumar', 'ravi');
      await asha.load([200_00, 100_00, 90_00, 50_00, 20_00, 20_00, 10_00, 5_00, 2_00, 2_00, 1_00]);
    });

    it('credits the receiver and refunds change to the payer, once', async () => {
      bank.advance(3600);
      const payment = asha.pay(ravi.paymentRequest(), 95_00, [100_00]);
      const id = b64(paymentIdOf(payment));
      bank.advance(600);

      const up = await ravi.call('POST', '/v1/settlement', { received: [{ payment: b64(payment), receivedAt: bank.ctx.clock() - 60 }], sent: [] });
      assert.equal(up.status, 200);
      assert.deepEqual(up.body.settledReceived, [id]);
      assert.equal(up.body.creditedPaise, 95_00);
      assert.equal(up.body.onlineBalancePaise, START + 95_00);
      assert.equal(await balance(asha), START - 500_00 + 5_00);

      // Re-upload by the receiver and upload by the payer are idempotent.
      const again = await ravi.call('POST', '/v1/settlement', { received: [{ payment: b64(payment), receivedAt: bank.ctx.clock() }] });
      assert.deepEqual(again.body.settledReceived, [id]);
      assert.equal(again.body.creditedPaise, 0);
      const payer = await asha.call('POST', '/v1/settlement', { sent: [b64(payment)] });
      assert.deepEqual(payer.body.settledSent, [id]);
      assert.equal(payer.body.refundedPaise, 0);
      assert.equal(await balance(ravi), START + 95_00);
      assert.equal(await balance(asha), START - 500_00 + 5_00);

      // The spent note drops out of the next lease.
      const lease = await asha.refreshLease();
      assert.equal(lease.body.outstandingNoteIds.length, 10);
      assert.equal(lease.body.outstandingValuePaise, 400_00);

      const detail = await ravi.call('GET', `/v1/payments/${Buffer.from(id, 'base64').toString('hex')}`);
      assert.equal(detail.body.direction, 'RECEIVED');
      assert.equal(detail.body.counterpartyHandle, 'asha@dpay');
      assert.equal(detail.body.changeRefundedPaise, 5_00);
    });

    it('settles a payment when only the payer uploads it', async () => {
      const payment = asha.pay(ravi.paymentRequest(), 120_00, [100_00, 20_00]);
      const res = await asha.call('POST', '/v1/settlement', { sent: [b64(payment)] });
      assert.equal(res.body.settledSent.length, 1);
      assert.equal(await balance(ravi), START + 120_00);
    });

    it('only accepts uploads from the payment’s own receiver or payer', async () => {
      const mallory = new TestClient(bank, '9000000009');
      await mallory.onboard('Mallory', 'mallory');
      const payment = asha.pay(ravi.paymentRequest(), 10_00, [10_00]);
      const res = await mallory.call('POST', '/v1/settlement', { received: [{ payment: b64(payment), receivedAt: bank.ctx.clock() }], sent: [b64(payment)] });
      assert.deepEqual(res.body.rejections.map((r: any) => r.code), ['NOT_YOUR_PAYMENT', 'NOT_YOUR_PAYMENT']);
      assert.equal(await balance(mallory), START);
    });

    it('rejects tampered, misdirected and stale-lease payments', async () => {
      const good = asha.pay(ravi.paymentRequest(), 50_00, [50_00]);
      const tampered = Buffer.from(good);
      tampered[tampered.length - 70]! ^= 0x01; // inside the lease signature
      const mallory = new TestClient(bank, '9000000009');
      await mallory.onboard('Mallory', 'mallory');
      const toMallory = asha.pay(mallory.paymentRequest(), 20_00, [20_00]);

      const res = await ravi.call('POST', '/v1/settlement', {
        received: [
          { payment: b64(tampered), receivedAt: bank.ctx.clock() },
          { payment: b64(Buffer.from('not cbor')), receivedAt: bank.ctx.clock() },
          { payment: b64(toMallory), receivedAt: bank.ctx.clock() },
          { payment: b64(good), receivedAt: bank.ctx.clock() + 3600 },
        ],
      });
      assert.deepEqual(
        res.body.rejections.map((r: any) => [r.code, r.reason]),
        [
          ['INVALID_PAYMENT', 'BAD_ISSUER_SIGNATURE'],
          ['INVALID_PAYMENT', 'MALFORMED'],
          ['NOT_YOUR_PAYMENT', undefined],
          ['BAD_RECEIVE_TIME', undefined],
        ],
      );

      // A lease from 6 days ago: receivers must refuse it (offline > 5 days).
      bank.advance(6 * DAY);
      const late = asha.pay(ravi.paymentRequest(), 10_00, [10_00]);
      const lateRes = await ravi.call('POST', '/v1/settlement', { received: [{ payment: b64(late), receivedAt: bank.ctx.clock() }] });
      assert.deepEqual(lateRes.body.rejections[0].reason, 'LEASE_EXPIRED');
      assert.equal(await balance(ravi), START);
    });

    it('detects a double spend, freezes the payer and blocklists the wallet', async () => {
      const first = asha.pay(ravi.paymentRequest(), 200_00, [200_00]);
      // Compromised hardware: the same note key signs a second payment.
      const second = asha.pay(ravi.paymentRequest(), 150_00, [200_00], { allowReuse: true });
      const res = await ravi.call('POST', '/v1/settlement', {
        received: [
          { payment: b64(first), receivedAt: bank.ctx.clock() },
          { payment: b64(second), receivedAt: bank.ctx.clock() },
        ],
      });
      assert.equal(res.body.settledReceived.length, 1);
      assert.deepEqual(res.body.rejections.map((r: any) => r.code), ['DOUBLE_SPEND']);
      assert.equal(res.body.creditedPaise, 200_00);

      assert.equal((await asha.refreshLease()).body.error.code, 'WALLET_FROZEN');
      assert.equal((await asha.call('POST', '/v1/provisioning/challenge')).body.error.code, 'WALLET_FROZEN');
      const blocked = await ravi.call('GET', '/v1/blocklist');
      assert.deepEqual(blocked.body.walletIds, [b64(asha.walletId)]);

      const events = await bank.request('GET', '/v1/admin/fraud-events', { headers: { 'x-admin-key': 'test-admin-key-0123456789abcdef' } });
      assert.equal(events.body.events[0].kind, 'DOUBLE_SPEND');
    });

    it('credits a guaranteed double spend when the bank guarantees offline payments', async () => {
      const g = await createTestBank({ GUARANTEE_OFFLINE_PAYMENTS: 'true' });
      const a = new TestClient(g, '9876543210');
      const r = new TestClient(g, '9123456789');
      await a.onboard('A', 'aaa');
      await r.onboard('R', 'rrr');
      await a.load([2_00, 1_00]);
      const p1 = a.pay(r.paymentRequest(), 2_00, [2_00]);
      const p2 = a.pay(r.paymentRequest(), 2_00, [2_00], { allowReuse: true });
      const res = await r.call('POST', '/v1/settlement', {
        received: [p1, p2].map((p) => ({ payment: b64(p), receivedAt: g.ctx.clock() })),
      });
      assert.equal(res.body.settledReceived.length, 2);
      assert.equal(res.body.creditedPaise, 4_00);
      assert.equal((await a.refreshLease()).body.error.code, 'WALLET_FROZEN');
    });

    it('refuses payments whose notes were already refunded', async () => {
      const payment = asha.pay(ravi.paymentRequest(), 1_00, [1_00]);
      bank.advance(21 * DAY + 1); // past expiry + grace
      await asha.call('GET', '/v1/account'); // triggers the refund
      const res = await ravi.call('POST', '/v1/settlement', { received: [{ payment: b64(payment), receivedAt: T0 + 60 }] });
      assert.equal(res.body.rejections[0].code, 'NOTE_REFUNDED');
    });

    it('handles concurrent settlement of the same payment without false double spend or duplicate credit', async () => {
      const payment = asha.pay(ravi.paymentRequest(), 95_00, [100_00]);
      const id = b64(paymentIdOf(payment));
      const ashaBefore = await balance(asha);
      const raviBefore = await balance(ravi);

      // Both payer and receiver upload the same payment concurrently
      const [pRes, rRes] = await Promise.all([
        asha.call('POST', '/v1/settlement', { sent: [b64(payment)], received: [] }),
        ravi.call('POST', '/v1/settlement', { sent: [], received: [{ payment: b64(payment), receivedAt: bank.ctx.clock() }] }),
      ]);

      assert.equal(pRes.status, 200);
      assert.equal(rRes.status, 200);
      assert.deepEqual(pRes.body.settledSent, [id]);
      assert.deepEqual(rRes.body.settledReceived, [id]);
      assert.equal(pRes.body.rejections.length, 0);
      assert.equal(rRes.body.rejections.length, 0);

      // Asha's wallet must NOT be frozen as a false double spend
      const lease = await asha.refreshLease();
      assert.equal(lease.status, 200);

      // Balances must be credited and refunded exactly once
      assert.equal(await balance(ravi), raviBefore + 95_00);
      assert.equal(await balance(asha), ashaBefore + 5_00);
    });

    it('prevents duplicate refund on concurrent lease refreshes with expired notes', async () => {
      const ashaBefore = await balance(asha);
      // Advance past note expiry + grace
      bank.advance(21 * DAY + 1);

      // Concurrently trigger lease refresh / account queries that invoke refundExpiredNotes
      const [r1, r2] = await Promise.all([
        asha.call('POST', '/v1/wallet/lease'),
        asha.call('GET', '/v1/account'),
      ]);

      assert.equal(r1.status, 200);
      assert.equal(r2.status, 200);

      // Asha loaded ₹500 before. Since notes expired unspent, she gets exactly ₹500 refunded once
      assert.equal(await balance(asha), ashaBefore + 500_00);
    });
  });

  describe('admin', () => {
    it('requires the admin key and credits accounts', async () => {
      const bank = await createTestBank();
      const asha = new TestClient(bank, '9876543210');
      await asha.onboard('Asha', 'asha');
      const path = '/v1/admin/accounts/9876543210/credit';
      assert.equal((await bank.request('POST', path, { body: { amountPaise: 100 } })).status, 403);
      const ok = await bank.request('POST', path, { body: { amountPaise: 1_000_00 }, headers: { 'x-admin-key': 'test-admin-key-0123456789abcdef' } });
      assert.equal(ok.body.onlineBalancePaise, START + 1_000_00);

      const freeze = await bank.request('POST', '/v1/admin/accounts/9876543210/freeze', { headers: { 'x-admin-key': 'test-admin-key-0123456789abcdef' } });
      assert.equal(freeze.body.frozen, true);
      assert.equal((await asha.refreshLease()).body.error.code, 'WALLET_FROZEN');
    });

    it('returns 404 JSON for unknown routes and validates bodies', async () => {
      const bank = await createTestBank();
      assert.equal((await bank.request('GET', '/v1/nope')).body.error.code, 'NOT_FOUND');
      const bad = await bank.request('POST', '/v1/auth/otp/verify', { body: { phone: '9876543210', code: 'abc' } });
      assert.equal(bad.body.error.code, 'INVALID_REQUEST');
    });
  });

  describe('mock bank & infinite money', () => {
    it('loads money from mock bank and queries bank account details', async () => {
      const bank = await createTestBank();
      const asha = new TestClient(bank, '9876543210');
      await asha.onboard('Asha Rao', 'asha');

      // Query linked mock bank account
      const accRes = await asha.call('GET', '/v1/bank/account');
      assert.equal(accRes.status, 200);
      assert.equal(accRes.body.infiniteMoney, true);
      assert.equal(accRes.body.accountNumber, '1009876543210');
      assert.equal(accRes.body.bankName, 'DPay Reserve Bank');
      assert.equal(accRes.body.onlineBalancePaise, START);

      // Load money from mock bank into DPay online balance
      const loadRes = await asha.call('POST', '/v1/bank/load', { amountPaise: 50_000_00 });
      assert.equal(loadRes.status, 200);
      assert.equal(loadRes.body.success, true);
      assert.equal(loadRes.body.amountPaise, 50_000_00);
      assert.equal(loadRes.body.newOnlineBalancePaise, START + 50_000_00);

      // Settle/withdraw from online balance back to mock bank account
      const withdrawRes = await asha.call('POST', '/v1/bank/withdraw', { amountPaise: 20_000_00 });
      assert.equal(withdrawRes.status, 200);
      assert.equal(withdrawRes.body.success, true);
      assert.equal(withdrawRes.body.remainingOnlineBalancePaise, START + 30_000_00);

      // Check transactions list
      const txRes = await asha.call('GET', '/v1/bank/transactions');
      assert.equal(txRes.status, 200);
      assert.equal(txRes.body.transactions.length, 2);
    });

    it('auto-funds shortfall when infinite money auto-load is enabled', async () => {
      // User starts with 0 balance, but MOCK_BANK_AUTO_LOAD is enabled
      const bank = await createTestBank({ STARTING_BALANCE_PAISE: '0', MOCK_BANK_AUTO_LOAD: 'true' });
      const asha = new TestClient(bank, '9876543210');
      await asha.onboard('Asha Rao', 'asha');

      // Online balance is initially 0
      assert.equal(await balance(asha), 0);

      // Load offline wallet with ₹3 (insufficient online balance)
      // Infinite money auto-funds the shortfall and note issuing succeeds!
      const res = await asha.load([2_00, 1_00]);
      assert.equal(res.status, 201);
      assert.equal(res.body.noteCertificates.length, 2);

      // Outstanding offline wallet is ₹3, online balance is 0 (since exactly ₹3 was auto-funded and debited)
      const summary = await asha.call('GET', '/v1/account');
      assert.equal(summary.body.offlineOutstandingPaise, 3_00);
    });

    it('supports /v1/central-bank alias for the Central Bank simulator', async () => {
      const bank = await createTestBank();
      const asha = new TestClient(bank, '9876543210');
      await asha.onboard('Asha Rao', 'asha');

      const res = await asha.call('GET', '/v1/central-bank/account');
      assert.equal(res.status, 200);
      assert.equal(res.body.bankName, 'DPay Reserve Bank');
      assert.equal(res.body.infiniteMoney, true);
    });
  });

  describe('production health & readiness probes', () => {
    it('returns 200 for liveness probe /health', async () => {
      const bank = await createTestBank();
      const res = await bank.request('GET', '/health');
      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'ok');
      assert.equal(res.body.service, 'dpay-backend');
    });

    it('returns 200 for readiness probe /health/ready with DB, Redis, and Issuer status', async () => {
      const bank = await createTestBank();
      const res = await bank.request('GET', '/health/ready');
      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'ready');
      assert.equal(res.body.checks.database, 'up');
      assert.equal(res.body.checks.redis, 'up');
      assert.equal(res.body.checks.issuerKey, 'loaded');
    });
  });

  describe('swagger & openapi documentation', () => {
    it('serves interactive swagger ui and raw openapi spec files', async () => {
      const bank = await createTestBank();

      // OpenAPI JSON
      const jsonRes = await bank.request('GET', '/docs/openapi.json');
      assert.equal(jsonRes.status, 200);
      assert.equal(jsonRes.body.openapi, '3.1.0');
      assert.equal(jsonRes.body.info.title.includes('DPay Backend API'), true);
      assert.equal(Object.keys(jsonRes.body.paths).length >= 25, true);

      // OpenAPI YAML
      const yamlRes = await bank.request('GET', '/docs/openapi.yaml');
      assert.equal(yamlRes.status, 200);
      assert.equal(typeof yamlRes.body === 'string' || typeof yamlRes.body === 'object', true);

      // Swagger UI redirect
      const redirectRes = await bank.request('GET', '/api-docs');
      assert.equal(redirectRes.status === 301 || redirectRes.status === 302, true);
    });
  });
