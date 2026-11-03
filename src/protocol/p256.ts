import { createPublicKey, ECDH, sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto';

/**
 * NIST P-256 helpers: compressed point encoding and domain-separated ECDSA with raw r‖s
 * signatures. Port of `wallet-core/.../crypto/P256.kt`. P-256 is the only curve the protocol allows.
 */
export const COMPRESSED_KEY_SIZE = 33;
export const RAW_SIGNATURE_SIZE = 64;

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

export class InvalidKeyError extends Error {}

/** Domain separation tags. Each signature covers `tag ‖ 0x00 ‖ message`. */
export const SigningDomain = {
  WALLET_CERTIFICATE: 'DPAY/v1/wallet-certificate',
  NOTE_CERTIFICATE: 'DPAY/v1/note-certificate',
  NOTE_SPEND: 'DPAY/v1/note-spend',
  WALLET_LEASE: 'DPAY/v1/wallet-lease',
} as const;
export type SigningDomain = (typeof SigningDomain)[keyof typeof SigningDomain];

export function domainInput(domain: SigningDomain, message: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), message]);
}

/** Decodes a compressed point, validating that it lies on the curve. */
export function decompress(encoded: Uint8Array): KeyObject {
  if (encoded.length !== COMPRESSED_KEY_SIZE) throw new InvalidKeyError('bad compressed key size');
  const prefix = encoded[0];
  if (prefix !== 0x02 && prefix !== 0x03) throw new InvalidKeyError('bad point prefix');
  const x = BigInt('0x' + Buffer.from(encoded.subarray(1)).toString('hex'));
  if (x >= P) throw new InvalidKeyError('x out of range');
  let uncompressed: Buffer;
  try {
    uncompressed = ECDH.convertKey(Buffer.from(encoded), 'prime256v1', undefined, undefined, 'uncompressed') as Buffer;
  } catch {
    throw new InvalidKeyError('point not on curve');
  }
  return createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: uncompressed.subarray(1, 33).toString('base64url'),
      y: uncompressed.subarray(33, 65).toString('base64url'),
    },
    format: 'jwk',
  });
}

/** Compressed SEC1 encoding (33 bytes) of a P-256 public key. */
export function compress(key: KeyObject): Buffer {
  if (key.asymmetricKeyType !== 'ec') throw new InvalidKeyError('not an EC key');
  const jwk = key.export({ format: 'jwk' });
  if (jwk.crv !== 'P-256' || !jwk.x || !jwk.y) throw new InvalidKeyError('not a P-256 key');
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  if (x.length !== 32 || y.length !== 32) throw new InvalidKeyError('bad coordinate size');
  return Buffer.concat([Buffer.from([(y[31]! & 1) === 1 ? 0x03 : 0x02]), x]);
}

/** Verifies a raw r‖s signature over the domain-separated message. Never throws on bad input. */
export function verify(key: KeyObject, domain: SigningDomain, message: Uint8Array, rawSignature: Uint8Array): boolean {
  if (rawSignature.length !== RAW_SIGNATURE_SIZE) return false;
  try {
    return nodeVerify('sha256', domainInput(domain, message), { key, dsaEncoding: 'ieee-p1363' }, rawSignature);
  } catch {
    return false;
  }
}

/** Signs with SHA256withECDSA and returns raw r‖s (64 bytes). */
export function sign(privateKey: KeyObject, domain: SigningDomain, message: Uint8Array): Buffer {
  return nodeSign('sha256', domainInput(domain, message), { key: privateKey, dsaEncoding: 'ieee-p1363' });
}
