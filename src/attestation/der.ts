/** Minimal strict DER reader: enough to walk X.509 extensions and the Android KeyDescription. */

export class DerError extends Error {}

export const TagClass = { UNIVERSAL: 0, APPLICATION: 1, CONTEXT: 2, PRIVATE: 3 } as const;

export const Universal = {
  BOOLEAN: 1,
  INTEGER: 2,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  ENUMERATED: 10,
  SEQUENCE: 16,
  SET: 17,
} as const;

export interface Tlv {
  readonly tagClass: number;
  readonly constructed: boolean;
  readonly tagNumber: number;
  /** Content octets. */
  readonly value: Buffer;
  /** The complete encoding (header + content). */
  readonly raw: Buffer;
}

const MAX_DEPTH = 32;

export function readTlv(data: Buffer, offset = 0): { tlv: Tlv; next: number } {
  let pos = offset;
  const byte = (): number => {
    if (pos >= data.length) throw new DerError('truncated DER');
    return data[pos++]!;
  };
  const first = byte();
  const tagClass = first >>> 6;
  const constructed = (first & 0x20) !== 0;
  let tagNumber = first & 0x1f;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    for (let i = 0; ; i++) {
      if (i > 4) throw new DerError('tag number too large');
      const b = byte();
      if (i === 0 && b === 0x80) throw new DerError('non-minimal tag');
      tagNumber = tagNumber * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }
  let length = byte();
  if (length === 0x80) throw new DerError('indefinite length not allowed in DER');
  if (length > 0x80) {
    const count = length & 0x7f;
    if (count > 4) throw new DerError('length too large');
    length = 0;
    for (let i = 0; i < count; i++) {
      const b = byte();
      if (i === 0 && b === 0) throw new DerError('non-minimal length');
      length = length * 256 + b;
    }
    if (length < 0x80) throw new DerError('non-minimal length');
  }
  if (pos + length > data.length) throw new DerError('DER length exceeds input');
  const tlv: Tlv = {
    tagClass,
    constructed,
    tagNumber,
    value: data.subarray(pos, pos + length),
    raw: data.subarray(offset, pos + length),
  };
  return { tlv, next: pos + length };
}

/** Parses exactly one TLV spanning all of [data]. */
export function parseDer(data: Buffer): Tlv {
  const { tlv, next } = readTlv(data, 0);
  if (next !== data.length) throw new DerError('trailing DER bytes');
  return tlv;
}

export function children(tlv: Tlv, depth = 0): Tlv[] {
  if (depth > MAX_DEPTH) throw new DerError('DER nesting too deep');
  if (!tlv.constructed) throw new DerError('expected constructed DER value');
  const out: Tlv[] = [];
  let pos = 0;
  while (pos < tlv.value.length) {
    const { tlv: child, next } = readTlv(tlv.value, pos);
    out.push(child);
    pos = next;
  }
  return out;
}

export function expectUniversal(tlv: Tlv, tag: number, what: string): Tlv {
  if (tlv.tagClass !== TagClass.UNIVERSAL || tlv.tagNumber !== tag) throw new DerError(`expected ${what}`);
  return tlv;
}

export function sequence(tlv: Tlv, what = 'SEQUENCE'): Tlv[] {
  return children(expectUniversal(tlv, Universal.SEQUENCE, what));
}

export function integer(tlv: Tlv): bigint {
  if (tlv.tagClass !== TagClass.UNIVERSAL || (tlv.tagNumber !== Universal.INTEGER && tlv.tagNumber !== Universal.ENUMERATED)) {
    throw new DerError('expected INTEGER/ENUMERATED');
  }
  if (tlv.value.length === 0) throw new DerError('empty INTEGER');
  let v = BigInt('0x' + tlv.value.toString('hex'));
  if ((tlv.value[0]! & 0x80) !== 0) v -= 1n << BigInt(tlv.value.length * 8);
  return v;
}

export function smallInt(tlv: Tlv): number {
  const v = integer(tlv);
  if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < BigInt(Number.MIN_SAFE_INTEGER)) throw new DerError('integer too large');
  return Number(v);
}

export function boolean(tlv: Tlv): boolean {
  expectUniversal(tlv, Universal.BOOLEAN, 'BOOLEAN');
  if (tlv.value.length !== 1) throw new DerError('bad BOOLEAN');
  return tlv.value[0] !== 0;
}

export function octetString(tlv: Tlv): Buffer {
  return expectUniversal(tlv, Universal.OCTET_STRING, 'OCTET STRING').value;
}

export function oid(tlv: Tlv): string {
  const v = expectUniversal(tlv, Universal.OID, 'OBJECT IDENTIFIER').value;
  if (v.length === 0) throw new DerError('empty OID');
  const parts: number[] = [];
  let acc = 0;
  for (const b of v) {
    acc = acc * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  const first = parts.shift()!;
  const head = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80];
  return [...head, ...parts].join('.');
}
