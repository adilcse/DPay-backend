import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  verify,
  type KeyObject,
} from 'node:crypto';
import * as P256 from '../src/protocol/p256.ts';
import {
  buildRequestAad,
  buildResponseAad,
  decryptAesGcm,
  deriveChannelKeys,
  encryptAesGcm,
  SecureChannelConstants,
} from '../src/protocol/secureChannel.ts';
import { createTestBank } from './helpers.ts';

describe('Advance DHE & Payload Encryption', () => {
  it('derives identical symmetric keys between client and server via ECDH + HKDF', () => {
    const serverPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const clientPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    const clientSecret = Buffer.from(diffieHellman({ publicKey: serverPair.publicKey, privateKey: clientPair.privateKey }));
    const serverSecret = Buffer.from(diffieHellman({ publicKey: clientPair.publicKey, privateKey: serverPair.privateKey }));
    assert.deepEqual(clientSecret, serverSecret);

    const clientKeys = deriveChannelKeys(clientSecret);
    const serverKeys = deriveChannelKeys(serverSecret);

    assert.deepEqual(clientKeys.clientKey, serverKeys.clientKey);
    assert.deepEqual(clientKeys.serverKey, serverKeys.serverKey);
    assert.notDeepEqual(clientKeys.clientKey, clientKeys.serverKey);
  });

  it('successfully encrypts request from client and decrypts on server, and vice versa', async () => {
    const bank = await createTestBank();
    const serverPublicKey = bank.ctx.issuer.publicKey;

    // Client generates ephemeral keypair
    const clientPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const clientPubCompressed = P256.compress(clientPair.publicKey);

    // Client computes shared secret & derives keys
    const clientShared = Buffer.from(diffieHellman({ publicKey: serverPublicKey, privateKey: clientPair.privateKey }));
    const { clientKey, serverKey } = deriveChannelKeys(clientShared);

    // Client prepares payload
    const now = bank.ctx.clock();
    const requestId = 'req-test-otp-12345';
    const method = 'POST';
    const path = '/v1/auth/otp';
    const rawPayload = JSON.stringify({ phone: '9876543210' });

    const iv = randomBytes(12);
    const ephHex = clientPubCompressed.toString('hex');
    const aad = buildRequestAad(1, method, path, now, requestId, ephHex);
    const { ciphertext, tag } = encryptAesGcm(clientKey, iv, Buffer.from(rawPayload, 'utf8'), aad);

    const encryptedEnvelope = {
      _encrypted: true,
      v: 1,
      keyId: bank.ctx.issuer.keyId,
      ephemeralPublicKey: clientPubCompressed.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      timestamp: now,
      requestId,
    };

    // Send encrypted request to server
    const res = await bank.request('POST', '/v1/auth/otp', { body: encryptedEnvelope });
    assert.equal(res.status, 200);

    // Server must respond with encrypted envelope
    assert.equal(res.body._encrypted, true);
    assert.equal(res.body.requestId, requestId);

    // Client decrypts server response
    const respIv = Buffer.from(res.body.iv, 'base64');
    const respTag = Buffer.from(res.body.tag, 'base64');
    const respCt = Buffer.from(res.body.ciphertext, 'base64');
    const respAad = buildResponseAad(1, 200, res.body.timestamp, requestId);

    const decryptedRespBuf = decryptAesGcm(serverKey, respIv, respCt, respTag, respAad);
    const respData = JSON.parse(decryptedRespBuf.toString('utf8'));

    assert.equal(respData.phone, '9876543210');
    assert.ok(respData.expiresAt > now);
  });

  it('rejects tampered ciphertext with tag mismatch', async () => {
    const bank = await createTestBank();
    const serverPublicKey = bank.ctx.issuer.publicKey;
    const clientPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const clientPubCompressed = P256.compress(clientPair.publicKey);
    const clientShared = Buffer.from(diffieHellman({ publicKey: serverPublicKey, privateKey: clientPair.privateKey }));
    const { clientKey } = deriveChannelKeys(clientShared);

    const now = bank.ctx.clock();
    const requestId = 'req-tamper-test-1';
    const iv = randomBytes(12);
    const ephHex = clientPubCompressed.toString('hex');
    const aad = buildRequestAad(1, 'POST', '/v1/auth/otp', now, requestId, ephHex);
    const { ciphertext, tag } = encryptAesGcm(clientKey, iv, Buffer.from(JSON.stringify({ phone: '9876543210' }), 'utf8'), aad);

    // Tamper 1 byte of ciphertext
    ciphertext[0] ^= 0x55;

    const envelope = {
      _encrypted: true,
      v: 1,
      ephemeralPublicKey: clientPubCompressed.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      timestamp: now,
      requestId,
    };

    const res = await bank.request('POST', '/v1/auth/otp', { body: envelope });
    assert.equal(res.status, 400);
    assert.equal(res.body.error.code, 'INVALID_REQUEST');
  });

  it('rejects replay attacks with duplicate requestId', async () => {
    const bank = await createTestBank();
    const serverPublicKey = bank.ctx.issuer.publicKey;
    const clientPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const clientPubCompressed = P256.compress(clientPair.publicKey);
    const clientShared = Buffer.from(diffieHellman({ publicKey: serverPublicKey, privateKey: clientPair.privateKey }));
    const { clientKey } = deriveChannelKeys(clientShared);

    const now = bank.ctx.clock();
    const requestId = 'req-replay-test-nonce';
    const iv = randomBytes(12);
    const ephHex = clientPubCompressed.toString('hex');
    const aad = buildRequestAad(1, 'POST', '/v1/auth/otp', now, requestId, ephHex);
    const { ciphertext, tag } = encryptAesGcm(clientKey, iv, Buffer.from(JSON.stringify({ phone: '9876543210' }), 'utf8'), aad);

    const envelope = {
      _encrypted: true,
      v: 1,
      ephemeralPublicKey: clientPubCompressed.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      timestamp: now,
      requestId,
    };

    // First request succeeds
    const firstRes = await bank.request('POST', '/v1/auth/otp', { body: envelope });
    assert.equal(firstRes.status, 200);

    // Second request with same requestId is rejected
    const secondRes = await bank.request('POST', '/v1/auth/otp', { body: envelope });
    assert.equal(secondRes.status, 400);
    assert.match(secondRes.body.error.message, /replay attack/i);
  });

  it('rejects stale requests outside clock skew window', async () => {
    const bank = await createTestBank();
    const serverPublicKey = bank.ctx.issuer.publicKey;
    const clientPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const clientPubCompressed = P256.compress(clientPair.publicKey);
    const clientShared = Buffer.from(diffieHellman({ publicKey: serverPublicKey, privateKey: clientPair.privateKey }));
    const { clientKey } = deriveChannelKeys(clientShared);

    // 5 minutes in the past
    const staleTime = bank.ctx.clock() - 300;
    const requestId = 'req-stale-time-test';
    const iv = randomBytes(12);
    const ephHex = clientPubCompressed.toString('hex');
    const aad = buildRequestAad(1, 'POST', '/v1/auth/otp', staleTime, requestId, ephHex);
    const { ciphertext, tag } = encryptAesGcm(clientKey, iv, Buffer.from(JSON.stringify({ phone: '9876543210' }), 'utf8'), aad);

    const envelope = {
      _encrypted: true,
      v: 1,
      ephemeralPublicKey: clientPubCompressed.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      timestamp: staleTime,
      requestId,
    };

    const res = await bank.request('POST', '/v1/auth/otp', { body: envelope });
    assert.equal(res.status, 400);
    assert.match(res.body.error.message, /clock skew/i);
  });

  it('supports GET requests with encrypted headers and encrypted responses', async () => {
    const bank = await createTestBank();
    const serverPublicKey = bank.ctx.issuer.publicKey;
    const clientPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const clientPubCompressed = P256.compress(clientPair.publicKey);
    const clientShared = Buffer.from(diffieHellman({ publicKey: serverPublicKey, privateKey: clientPair.privateKey }));
    const { serverKey } = deriveChannelKeys(clientShared);

    const now = bank.ctx.clock();
    const requestId = 'req-get-encrypted-test';

    const res = await bank.request('GET', '/v1/handles/suggestion?fullName=Asha+Rao', {
      headers: {
        'x-dpay-encrypted': 'true',
        'x-dpay-ephemeral-key': clientPubCompressed.toString('base64'),
        'x-dpay-timestamp': String(now),
        'x-dpay-request-id': requestId,
      },
    });

    assert.equal(res.status, 200);
    assert.equal(res.body._encrypted, true);

    const respIv = Buffer.from(res.body.iv, 'base64');
    const respTag = Buffer.from(res.body.tag, 'base64');
    const respCt = Buffer.from(res.body.ciphertext, 'base64');
    const respAad = buildResponseAad(1, 200, res.body.timestamp, requestId);

    const decryptedBuf = decryptAesGcm(serverKey, respIv, respCt, respTag, respAad);
    const data = JSON.parse(decryptedBuf.toString('utf8'));
    assert.ok(data.suggestion);
  });

  it('completes 2-way Advance DHE Key Exchange Handshake (/v1/crypto/handshake)', async () => {
    const bank = await createTestBank();
    const clientPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const clientPubCompressed = P256.compress(clientPair.publicKey);
    const clientNonce = randomBytes(16);
    const now = bank.ctx.clock();

    const handshakeReq = {
      clientEphemeralPublicKey: clientPubCompressed.toString('base64'),
      clientNonce: clientNonce.toString('base64'),
      timestamp: now,
    };

    const res = await bank.request('POST', '/v1/crypto/handshake', { body: handshakeReq });
    assert.equal(res.status, 200);

    const {
      channelId,
      serverEphemeralPublicKey,
      serverNonce,
      signature,
      keyId,
      expiresAt,
    } = res.body;

    assert.ok(channelId);
    assert.ok(serverEphemeralPublicKey);
    assert.ok(serverNonce);
    assert.ok(signature);
    assert.equal(keyId, bank.ctx.issuer.keyId);
    assert.ok(expiresAt > now);

    // Client verifies server signature using pinned Issuer key
    const serverPubBytes = Buffer.from(serverEphemeralPublicKey, 'base64');
    const serverNonceBytes = Buffer.from(serverNonce, 'base64');
    const sigBytes = Buffer.from(signature, 'base64');

    const tsBuffer = Buffer.alloc(8);
    tsBuffer.writeBigInt64BE(BigInt(now));
    const transcript = Buffer.concat([
      Buffer.from(SecureChannelConstants.HANDSHAKE_DOMAIN, 'utf8'),
      Buffer.from([0]),
      serverPubBytes,
      clientPubCompressed,
      serverNonceBytes,
      clientNonce,
      tsBuffer,
    ]);

    const isSigValid = verify('sha256', transcript, bank.ctx.issuer.publicKey, sigBytes);
    assert.equal(isSigValid, true, 'Server handshake signature must be valid');

    // Client computes shared secret
    const serverEphKeyObj = P256.decompress(serverPubBytes);
    const sharedSecret = Buffer.from(diffieHellman({ publicKey: serverEphKeyObj, privateKey: clientPair.privateKey }));
    assert.equal(sharedSecret.length, 32);

    const { clientKey, serverKey } = deriveChannelKeys(sharedSecret);
    assert.ok(clientKey);
    assert.ok(serverKey);
  });
});
