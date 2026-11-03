import * as der from './der.ts';
import { DerError, TagClass, type Tlv } from './der.ts';

/** OID of the Android Keystore attestation extension (KeyDescription). */
export const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17';

export const SecurityLevel = { SOFTWARE: 0, TRUSTED_ENVIRONMENT: 1, STRONG_BOX: 2 } as const;
export const VerifiedBootState = { VERIFIED: 0, SELF_SIGNED: 1, UNVERIFIED: 2, FAILED: 3 } as const;

/** AuthorizationList tags used by the DPay checks (Keymaster/KeyMint `Tag` numbers). */
export const AuthTag = {
  PURPOSE: 1,
  ALGORITHM: 2,
  KEY_SIZE: 3,
  DIGEST: 5,
  EC_CURVE: 10,
  USAGE_COUNT_LIMIT: 405,
  NO_AUTH_REQUIRED: 503,
  UNLOCKED_DEVICE_REQUIRED: 509,
  ROOT_OF_TRUST: 704,
  ATTESTATION_APPLICATION_ID: 709,
} as const;

export const KM_PURPOSE_SIGN = 2;
export const KM_ALGORITHM_EC = 3;
export const KM_EC_CURVE_P256 = 1;

export interface RootOfTrust {
  readonly deviceLocked: boolean;
  readonly verifiedBootState: number;
}

export interface AttestationApplicationId {
  readonly packageNames: readonly string[];
  /** SHA-256 digests of the app's signing certificates, lowercase hex. */
  readonly signatureDigests: readonly string[];
}

export class AuthorizationList {
  private readonly fields: ReadonlyMap<number, Tlv>;

  constructor(fields: ReadonlyMap<number, Tlv>) {
    this.fields = fields;
  }

  has(tag: number): boolean {
    return this.fields.has(tag);
  }

  int(tag: number): number | undefined {
    const f = this.fields.get(tag);
    return f === undefined ? undefined : der.smallInt(f);
  }

  intSet(tag: number): number[] | undefined {
    const f = this.fields.get(tag);
    if (f === undefined) return undefined;
    der.expectUniversal(f, der.Universal.SET, 'SET OF INTEGER');
    return der.children(f).map(der.smallInt);
  }

  rootOfTrust(): RootOfTrust | undefined {
    const f = this.fields.get(AuthTag.ROOT_OF_TRUST);
    if (f === undefined) return undefined;
    const items = der.sequence(f, 'RootOfTrust');
    if (items.length < 3) throw new DerError('short RootOfTrust');
    return { deviceLocked: der.boolean(items[1]!), verifiedBootState: der.smallInt(items[2]!) };
  }

  attestationApplicationId(): AttestationApplicationId | undefined {
    const f = this.fields.get(AuthTag.ATTESTATION_APPLICATION_ID);
    if (f === undefined) return undefined;
    const items = der.sequence(der.parseDer(der.octetString(f)), 'AttestationApplicationId');
    if (items.length < 2) throw new DerError('short AttestationApplicationId');
    const packageNames = der.children(der.expectUniversal(items[0]!, der.Universal.SET, 'package infos')).map((info) => {
      const parts = der.sequence(info, 'AttestationPackageInfo');
      return der.octetString(parts[0]!).toString('utf8');
    });
    const signatureDigests = der
      .children(der.expectUniversal(items[1]!, der.Universal.SET, 'signature digests'))
      .map((d) => der.octetString(d).toString('hex'));
    return { packageNames, signatureDigests };
  }
}

export interface KeyDescription {
  readonly attestationVersion: number;
  readonly attestationSecurityLevel: number;
  readonly keyMintVersion: number;
  readonly keyMintSecurityLevel: number;
  readonly attestationChallenge: Buffer;
  readonly softwareEnforced: AuthorizationList;
  readonly hardwareEnforced: AuthorizationList;
}

function parseAuthorizationList(tlv: Tlv): AuthorizationList {
  const fields = new Map<number, Tlv>();
  for (const item of der.sequence(tlv, 'AuthorizationList')) {
    if (item.tagClass !== TagClass.CONTEXT || !item.constructed) throw new DerError('expected [n] EXPLICIT field');
    if (fields.has(item.tagNumber)) throw new DerError(`duplicate authorization tag ${item.tagNumber}`);
    const inner = der.children(item);
    if (inner.length !== 1) throw new DerError('bad EXPLICIT field');
    fields.set(item.tagNumber, inner[0]!);
  }
  return new AuthorizationList(fields);
}

/** Finds an extension's value (the OCTET STRING contents) in a DER X.509 certificate. */
export function findExtension(certificateDer: Buffer, wantedOid: string): Buffer | undefined {
  const [tbs] = der.sequence(der.parseDer(certificateDer), 'Certificate');
  if (!tbs) throw new DerError('missing tbsCertificate');
  const explicitExtensions = der.sequence(tbs, 'TBSCertificate').find((t) => t.tagClass === TagClass.CONTEXT && t.tagNumber === 3);
  if (!explicitExtensions) return undefined;
  const [extensions] = der.children(explicitExtensions);
  if (!extensions) return undefined;
  for (const ext of der.sequence(extensions, 'Extensions')) {
    const parts = der.sequence(ext, 'Extension');
    if (parts.length < 2) throw new DerError('short Extension');
    if (der.oid(parts[0]!) === wantedOid) return der.octetString(parts[parts.length - 1]!);
  }
  return undefined;
}

export function parseKeyDescription(extensionValue: Buffer): KeyDescription {
  const items = der.sequence(der.parseDer(extensionValue), 'KeyDescription');
  if (items.length < 8) throw new DerError('short KeyDescription');
  return {
    attestationVersion: der.smallInt(items[0]!),
    attestationSecurityLevel: der.smallInt(items[1]!),
    keyMintVersion: der.smallInt(items[2]!),
    keyMintSecurityLevel: der.smallInt(items[3]!),
    attestationChallenge: der.octetString(items[4]!),
    softwareEnforced: parseAuthorizationList(items[6]!),
    hardwareEnforced: parseAuthorizationList(items[7]!),
  };
}
