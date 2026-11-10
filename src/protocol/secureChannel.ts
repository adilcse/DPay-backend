import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  randomBytes,
  KeyObject,
} from 'node:crypto';
import { z } from 'zod';
import { BankError, BankException } from '../domain/errors.ts';
import { base64Bytes } from '../http/wire.ts';
import * as P256 from './p256.ts';

export const SecureChannelConstants = {
  VERSION: 1,
  NONCE_BYTES: 12,
  TAG_BYTES: 16,
  KEY_BYTES: 32,
  CLOCK_SKEW_SECONDS: 120,
  REPLAY_TTL_SECONDS: 300,
  SALT: Buffer.from('DPay-v1-ECDHE-Channel', 'utf8'),
  CLIENT_INFO: Buffer.from('DPay-v1-Client-To-Server-AES256GCM', 'utf8'),
  SERVER_INFO: Buffer.from('DPay-v1-Server-To-Client-AES256GCM', 'utf8'),
  HANDSHAKE_DOMAIN: 'DPAY/v1/dhe-handshake',
} as const;

export const EncryptedRequestSchema = z.object({
  _encrypted: z.literal(true),
  v: z.number().int().default(SecureChannelConstants.VERSION),
  keyId: z.number().int().optional(),
  ephemeralPublicKey: base64Bytes({ max: 128 }),
  iv: base64Bytes({ size: SecureChannelConstants.NONCE_BYTES }),
  tag: base64Bytes({ size: SecureChannelConstants.TAG_BYTES }),
  ciphertext: base64Bytes({ max: 10 * 1024 * 1024 }),
  timestamp: z.number().int(),
  requestId: z.string().min(8).max(128),
});

export type EncryptedRequestEnvelope = z.infer<typeof EncryptedRequestSchema>;

export interface EncryptedResponseEnvelope {
  _encrypted: true;
  v: number;
  iv: string;
  tag: string;
  ciphertext: string;
  timestamp: number;
  requestId: string;
}

/** Parses public key bytes into a KeyObject, handling compressed (33B), uncompressed (65B), or SPKI DER. */
export function parsePublicKey(input: Uint8Array | Buffer | KeyObject): KeyObject {
  if (input instanceof KeyObject) return input;
  const buf = Buffer.from(input);
  if (buf.length === P256.COMPRESSED_KEY_SIZE && (buf[0] === 0x02 || buf[0] === 0x03)) {
    return P256.decompress(buf);
  }
  if (buf.length === 65 && buf[0] === 0x04) {
    return createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: buf.subarray(1, 33).toString('base64url'),
        y: buf.subarray(33, 65).toString('base64url'),
      },
      format: 'jwk',
    });
  }
  try {
    return createPublicKey({ key: buf, format: 'der', type: 'spki' });
  } catch (e) {
    throw new BankException(BankError.INVALID_REQUEST, 'invalid public key format in secure channel');
  }
}

/** Computes ECDH shared secret and expands client/server symmetric keys via HKDF-SHA256. */
export function deriveChannelKeys(sharedSecret: Buffer): { clientKey: Buffer; serverKey: Buffer } {
  const clientKey = Buffer.from(
    hkdfSync(
      'sha256',
      sharedSecret,
      SecureChannelConstants.SALT,
      SecureChannelConstants.CLIENT_INFO,
      SecureChannelConstants.KEY_BYTES,
    ),
  );
  const serverKey = Buffer.from(
    hkdfSync(
      'sha256',
      sharedSecret,
      SecureChannelConstants.SALT,
      SecureChannelConstants.SERVER_INFO,
      SecureChannelConstants.KEY_BYTES,
    ),
  );
  return { clientKey, serverKey };
}

/** Canonical Associated Authenticated Data (AAD) for client request. */
export function buildRequestAad(
  version: number,
  method: string,
  path: string,
  timestamp: number,
  requestId: string,
  ephemeralPubHex: string,
): Buffer {
  return Buffer.from(`${version}:${method.toUpperCase()}:${path}:${timestamp}:${requestId}:${ephemeralPubHex}`, 'utf8');
}

/** Canonical Associated Authenticated Data (AAD) for server response. */
export function buildResponseAad(
  version: number,
  statusCode: number,
  timestamp: number,
  requestId: string,
): Buffer {
  return Buffer.from(`${version}:response:${statusCode}:${timestamp}:${requestId}`, 'utf8');
}

/** Encrypts plaintext buffer using AES-256-GCM. */
export function encryptAesGcm(
  key: Buffer,
  iv: Buffer,
  plaintext: Buffer,
  aad: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag };
}

/** Decrypts ciphertext buffer using AES-256-GCM. */
export function decryptAesGcm(
  key: Buffer,
  iv: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
  aad: Buffer,
): Buffer {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new BankException(BankError.INVALID_REQUEST, 'payload decryption or authentication tag check failed');
  }
}

export interface DecryptedRequestResult {
  payload: unknown;
  serverKey: Buffer;
  clientKey: Buffer;
  requestId: string;
  timestamp: number;
}

/**
 * Decrypts an incoming client request envelope using ECDH (Advance DHE) + AES-256-GCM.
 */
export function decryptRequestEnvelope(
  envelope: EncryptedRequestEnvelope,
  serverPrivateKey: KeyObject,
  method: string,
  path: string,
  nowSeconds: number,
): DecryptedRequestResult {
  // 1. Timestamp Freshness check (prevent stale/replayed requests)
  if (Math.abs(nowSeconds - envelope.timestamp) > SecureChannelConstants.CLOCK_SKEW_SECONDS) {
    throw new BankException(BankError.INVALID_REQUEST, 'request timestamp expired or out of allowed clock skew');
  }

  // 2. Compute Advance DHE shared secret
  const clientKeyObj = parsePublicKey(envelope.ephemeralPublicKey);
  const sharedSecret = Buffer.from(diffieHellman({ publicKey: clientKeyObj, privateKey: serverPrivateKey }));

  // 3. HKDF key derivation
  const { clientKey, serverKey } = deriveChannelKeys(sharedSecret);

  // 4. Validate and decrypt with AAD
  const ephHex = Buffer.from(envelope.ephemeralPublicKey).toString('hex');
  const aad = buildRequestAad(envelope.v, method, path, envelope.timestamp, envelope.requestId, ephHex);
  const decryptedBuf = decryptAesGcm(clientKey, envelope.iv, envelope.ciphertext, envelope.tag, aad);

  // 5. Parse JSON payload
  let payload: unknown;
  try {
    payload = JSON.parse(decryptedBuf.toString('utf8'));
  } catch {
    throw new BankException(BankError.INVALID_REQUEST, 'decrypted payload is not valid JSON');
  }

  return {
    payload,
    serverKey,
    clientKey,
    requestId: envelope.requestId,
    timestamp: envelope.timestamp,
  };
}

/**
 * Encrypts a response payload using the session's derived serverKey + AES-256-GCM.
 */
export function encryptResponseEnvelope(
  data: unknown,
  serverKey: Buffer,
  statusCode: number,
  requestId: string,
  nowSeconds: number,
): EncryptedResponseEnvelope {
  const plaintext = Buffer.from(JSON.stringify(data ?? {}), 'utf8');
  const iv = randomBytes(SecureChannelConstants.NONCE_BYTES);
  const aad = buildResponseAad(SecureChannelConstants.VERSION, statusCode, nowSeconds, requestId);
  const { ciphertext, tag } = encryptAesGcm(serverKey, iv, plaintext, aad);

  return {
    _encrypted: true,
    v: SecureChannelConstants.VERSION,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    timestamp: nowSeconds,
    requestId,
  };
}
