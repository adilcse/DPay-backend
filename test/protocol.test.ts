import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import * as cbor from '../src/protocol/cbor.ts';
import { CborError } from '../src/protocol/cbor.ts';
import { isValidDenominationPlan, planDenominations } from '../src/protocol/denominations.ts';
import { isValidLocalPart, suggestHandle } from '../src/protocol/handles.ts';
import { Issuer } from '../src/protocol/issuer.ts';
import { NoteCertificate, ProtocolError, WalletCertificate, WalletLease } from '../src/protocol/messages.ts';
import * as P256 from '../src/protocol/p256.ts';

const hexBytes = (s: string) => Buffer.from(s.replace(/\s/g, ''), 'hex');

describe('strict CBOR', () => {
  it('round-trips and encodes canonically', () => {
    const value = cbor.map([
      [10, cbor.array([cbor.bytes(Buffer.from([1, 2]))])],
      [1, cbor.uint(1)],
      [2, cbor.text('é')],
      [3, cbor.uint(500_000)],
      [4, cbor.uint(2n ** 40n)],
    ]);
    const encoded = cbor.encode(value);
    assert.equal(encoded.toString('hex'), 'a5' + '0101' + '0262c3a9' + '031a0007a120' + '041b0000010000000000' + '0a81420102');
    assert.deepEqual(cbor.encode(cbor.decode(encoded)), encoded);
  });

  it('rejects non-canonical encodings', () => {
    const bad = {
      'non-minimal int': '1817',
      'non-minimal 2-byte': '1900ff',
      'unsorted keys': 'a2020101 01'.replace(/ /g, '') + '01',
      'duplicate keys': 'a201010101',
      'trailing bytes': '0000',
      'indefinite array': '9fff',
      'negative int': '20',
      'float': 'f93c00',
      'text map key': 'a1616101',
      'invalid utf-8': '62c328',
      'length beyond input': '45010203',
      'over 63 bits': '1bffffffffffffffff',
    };
    for (const [name, hex] of Object.entries(bad)) {
      assert.throws(() => cbor.decode(hexBytes(hex)), CborError, name);
    }
  });

  it('keeps a leading BOM in text (no silent normalization)', () => {
    const decoded = cbor.decode(hexBytes('63efbbbf'));
    assert.equal(decoded.kind === 'text' && decoded.value, '﻿');
  });

  it('rejects unexpected schema keys', () => {
    const m = cbor.asMap(cbor.decode(cbor.encode(cbor.map([[1, cbor.uint(1)], [9, cbor.uint(2)]]))));
    assert.throws(() => m.requireExactKeys(1, 2), CborError);
  });
});

describe('P-256', () => {
  it('compresses and decompresses keys and rejects off-curve points', () => {
    const issuer = Issuer.demo();
    const compressed = P256.compress(issuer.publicKey);
    assert.equal(compressed.length, 33);
    assert.deepEqual(P256.compress(P256.decompress(compressed)), compressed);
    assert.throws(() => P256.decompress(Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, 0xff)])), P256.InvalidKeyError);
    assert.throws(() => P256.decompress(Buffer.concat([Buffer.from([0x04]), compressed.subarray(1)])), P256.InvalidKeyError);
  });
});

describe('issuer', () => {
  const issuer = Issuer.demo();

  it('uses the same demo key as the app FakeIssuer', () => {
    assert.equal(
      issuer.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMLC3J4b+SqjZZtsbUxcXVyFpiRFmPENja3vzAAb3pLr2s5J4FgmMyBbBkXvQj9nJ' +
        'o0KU8L6jcuUBI7uA6ZgWCQ==',
    );
  });

  it('signs certificates that verify, and detects tampering', () => {
    const walletKey = P256.compress(issuer.publicKey);
    const cert = issuer.walletCertificate(Buffer.alloc(16, 7), walletKey, 'asha@dpay', 2_000_000_000);
    const parsed = WalletCertificate.decodeAndVerify(cert, issuer.trustAnchors, 1_900_000_000);
    assert.equal(parsed.displayName, 'asha@dpay');
    assert.throws(
      () => WalletCertificate.decodeAndVerify(cert, issuer.trustAnchors, 2_000_000_301),
      (e: unknown) => e instanceof ProtocolError && e.reason === 'EXPIRED',
    );
    const tampered = Buffer.from(cert);
    tampered[tampered.indexOf(Buffer.from('asha'))] = 'b'.charCodeAt(0);
    assert.throws(
      () => WalletCertificate.decodeAndVerify(tampered, issuer.trustAnchors, 1_900_000_000),
      (e: unknown) => e instanceof ProtocolError && e.reason === 'BAD_ISSUER_SIGNATURE',
    );
    const note = issuer.noteCertificate(Buffer.alloc(16, 1), Buffer.alloc(16, 7), 50_000, walletKey, 2_000_000_000);
    assert.equal(NoteCertificate.decodeAndVerify(note, issuer.trustAnchors).value, 50_000);
  });

  it('computes the ledger digest independent of order', () => {
    const a = Buffer.alloc(16, 0x01);
    const b = Buffer.alloc(16, 0xf0);
    assert.deepEqual(WalletLease.ledgerDigest([a, b]), WalletLease.ledgerDigest([b, a]));
    assert.notDeepEqual(WalletLease.ledgerDigest([a]), WalletLease.ledgerDigest([b]));
  });
});

describe('denominations (DenominationPlanner port)', () => {
  it('plans ₹5,000 as 15 notes (minimal) and 16 notes (change-heavy)', () => {
    const minimal = planDenominations(5_000_00, false);
    assert.equal(minimal.length, 15);
    assert.equal(minimal.reduce((a, b) => a + b, 0), 5_000_00);
    assert.deepEqual(minimal, [...minimal].sort((a, b) => b - a));

    const changeHeavy = planDenominations(5_000_00, true);
    assert.equal(changeHeavy.length, 16);
    assert.equal(changeHeavy.reduce((a, b) => a + b, 0), 5_000_00);
    assert.deepEqual(changeHeavy, [...changeHeavy].sort((a, b) => b - a));

    assert.equal(isValidDenominationPlan(minimal, 5_000_00), true);
    assert.equal(isValidDenominationPlan(changeHeavy, 5_000_00), true);
  });

  it('makes every whole-rupee amount payable exactly', () => {
    for (const rupees of [1, 7, 99, 500, 1234, 5000]) {
      const plan = planDenominations(rupees * 100).map((p) => p / 100);
      const reachable = new Set([0]);
      for (const n of plan) for (const s of [...reachable]) reachable.add(s + n);
      for (let r = 1; r <= rupees; r++) assert.ok(reachable.has(r), `load ₹${rupees}: ₹${r} not payable`);
    }
  });

  it('rejects fractional rupees', () => {
    assert.throws(() => planDenominations(100_50));
  });
});

describe('handles', () => {
  it('follows the name@dpay rules', () => {
    for (const ok of ['asha', 'asha.rao', 'a12', 'abc.def.ghi']) assert.ok(isValidLocalPart(ok), ok);
    for (const bad of ['as', '1asha', 'asha..rao', 'asha.', 'Asha', 'asha_rao', 'a'.repeat(31)]) assert.ok(!isValidLocalPart(bad), bad);
    assert.equal(suggestHandle('Asha K. Rao'), 'asha.k.rao');
    assert.equal(suggestHandle('  42 Ravi  '), 'ravi');
  });
});
