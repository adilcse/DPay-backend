import { createPrivateKey, createPublicKey, diffieHellman, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as P256 from './p256.ts';
import { SigningDomain } from './p256.ts';
import { NoteCertificate, SignedEnvelope, TrustAnchors, WalletCertificate, WalletLease } from './messages.ts';

/**
 * The FakeIssuer key from the app's `:bank` module (`FakeIssuer.kt`). **DEMO ONLY**: it is public
 * (shipped in the APK). Using it outside production lets debug builds, which pin this key, talk to
 * this server unchanged. Production refuses to start with it.
 */
export const DEMO_ISSUER_KEY_ID = 1;
const DEMO_PRIVATE_PKCS8 =
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgD1JPM9wmFSy0sXTcpvdyvDXGT/dv1XOoXz/EhM0WYuGhRANCAAQw' +
  'sLcnhv5KqNlm2xtTFxdXIWmJEWY8Q2Nre/MABvekuvazkngWCYzIFsGRe9CP2cmjQpTwvqNy5QEju4DpmBYJ';

/** Signs certificates, notes and leases. The bank only ever *signs*; device keys never leave the phone. */
export class Issuer {
  readonly keyId: number;
  readonly publicKey: KeyObject;
  readonly trustAnchors: TrustAnchors;
  readonly isDemoKey: boolean;
  private readonly privateKey: KeyObject;

  constructor(privateKey: KeyObject, keyId: number, isDemoKey = false, extraTrusted: ReadonlyMap<number, KeyObject> = new Map()) {
    if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      throw new Error('issuer key must be an EC P-256 private key');
    }
    this.privateKey = privateKey;
    this.keyId = keyId;
    this.isDemoKey = isDemoKey;
    this.publicKey = createPublicKey(privateKey);
    this.trustAnchors = new TrustAnchors(new Map([...extraTrusted, [keyId, this.publicKey]]));
  }

  static demo(): Issuer {
    const key = createPrivateKey({ key: Buffer.from(DEMO_PRIVATE_PKCS8, 'base64'), format: 'der', type: 'pkcs8' });
    return new Issuer(key, DEMO_ISSUER_KEY_ID, true);
  }

  static fromPemFile(path: string, keyId: number, extraTrusted?: ReadonlyMap<number, KeyObject>): Issuer {
    return new Issuer(createPrivateKey(readFileSync(path, 'utf8')), keyId, false, extraTrusted);
  }

  getPrivateKey(): KeyObject {
    return this.privateKey;
  }

  diffieHellman(peerPublicKey: KeyObject): Buffer {
    return Buffer.from(diffieHellman({ publicKey: peerPublicKey, privateKey: this.privateKey }));
  }

  walletCertificate(walletId: Buffer, walletKey: Buffer, displayName: string, notAfter: number): Buffer {
    const tbs = WalletCertificate.tbs(walletId, walletKey, displayName, notAfter, this.keyId);
    return SignedEnvelope.encode(tbs, P256.sign(this.privateKey, SigningDomain.WALLET_CERTIFICATE, tbs));
  }

  noteCertificate(noteId: Buffer, walletId: Buffer, value: number, noteKey: Buffer, notAfter: number): Buffer {
    const tbs = NoteCertificate.tbs(noteId, walletId, value, noteKey, notAfter, this.keyId);
    return SignedEnvelope.encode(tbs, P256.sign(this.privateKey, SigningDomain.NOTE_CERTIFICATE, tbs));
  }

  lease(args: {
    walletId: Buffer;
    walletKey: Buffer;
    sequence: number;
    issuedAt: number;
    notAfter: number;
    outstandingValue: number;
    noteIds: readonly Buffer[];
  }): Buffer {
    const tbs = WalletLease.tbs(
      args.walletId,
      args.walletKey,
      args.sequence,
      args.issuedAt,
      args.notAfter,
      args.outstandingValue,
      WalletLease.ledgerDigest(args.noteIds),
      this.keyId,
    );
    return SignedEnvelope.encode(tbs, P256.sign(this.privateKey, SigningDomain.WALLET_LEASE, tbs));
  }

  /** Public keys for pinning in the app: SPKI DER and compressed point, base64. */
  describeTrustAnchors(): Array<{ keyId: number; spki: string; compressed: string }> {
    return this.trustAnchors.ids().map((id) => {
      const key = this.trustAnchors.issuerKey(id);
      return {
        keyId: id,
        spki: key.export({ format: 'der', type: 'spki' }).toString('base64'),
        compressed: P256.compress(key).toString('base64'),
      };
    });
  }
}
