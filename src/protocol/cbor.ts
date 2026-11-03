/**
 * Minimal, strict CBOR (RFC 8949) subset used for every signed DPay structure.
 * Port of `wallet-core/.../cbor/Cbor.kt`. Keep the two in lockstep.
 *
 * Only unsigned integers, byte strings, text strings, arrays and maps with unsigned-integer keys
 * are supported. The decoder enforces deterministic encoding (minimal-length heads, definite
 * lengths, strictly ascending map keys, no trailing bytes), so every value has exactly one valid
 * byte representation.
 *
 * Integers are decoded as bigint (up to 2^63 - 1, as in Kotlin). Field accessors convert to
 * `number` and reject anything above `Number.MAX_SAFE_INTEGER`; protocol values (paise, epoch
 * seconds, sequences) are far below that.
 */

export class CborError extends Error {}

export type CborValue =
  | { readonly kind: 'uint'; readonly value: bigint }
  | { readonly kind: 'bytes'; readonly value: Uint8Array }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'array'; readonly items: readonly CborValue[] }
  | { readonly kind: 'map'; readonly entries: ReadonlyMap<number, CborValue> };

export const MAX_INPUT_BYTES = 64 * 1024;
const MAX_DEPTH = 8;
const MAX_UINT63 = (1n << 63n) - 1n;

const MAJOR_UINT = 0;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;

// --- Constructors -----------------------------------------------------------------------------

export function uint(value: number | bigint): CborValue {
  const v = typeof value === 'bigint' ? value : BigInt(checkSafeUint(value));
  if (v < 0n || v > MAX_UINT63) throw new RangeError('CBOR unsigned integer out of range');
  return { kind: 'uint', value: v };
}

export const bytes = (value: Uint8Array): CborValue => ({ kind: 'bytes', value });
export const text = (value: string): CborValue => ({ kind: 'text', value });
export const array = (items: readonly CborValue[]): CborValue => ({ kind: 'array', items });

export function map(entries: Iterable<readonly [number, CborValue]>): CborValue {
  const sorted = [...entries].sort((a, b) => a[0] - b[0]);
  const m = new Map<number, CborValue>();
  for (const [k, v] of sorted) {
    checkSafeUint(k);
    if (m.has(k)) throw new RangeError(`duplicate map key ${k}`);
    m.set(k, v);
  }
  return { kind: 'map', entries: m };
}

function checkSafeUint(n: number): number {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`not a non-negative safe integer: ${n}`);
  return n;
}

// --- Encoder ----------------------------------------------------------------------------------

export function encode(value: CborValue): Buffer {
  const out: Buffer[] = [];
  write(out, value);
  return Buffer.concat(out);
}

function write(out: Buffer[], value: CborValue): void {
  switch (value.kind) {
    case 'uint':
      head(out, MAJOR_UINT, value.value);
      break;
    case 'bytes':
      head(out, MAJOR_BYTES, BigInt(value.value.length));
      out.push(Buffer.from(value.value));
      break;
    case 'text': {
      const utf8 = Buffer.from(value.value, 'utf8');
      head(out, MAJOR_TEXT, BigInt(utf8.length));
      out.push(utf8);
      break;
    }
    case 'array':
      head(out, MAJOR_ARRAY, BigInt(value.items.length));
      for (const item of value.items) write(out, item);
      break;
    case 'map': {
      // For uint keys, ascending numeric order equals canonical bytewise order.
      const keys = [...value.entries.keys()].sort((a, b) => a - b);
      head(out, MAJOR_MAP, BigInt(keys.length));
      for (const k of keys) {
        head(out, MAJOR_UINT, BigInt(k));
        write(out, value.entries.get(k)!);
      }
      break;
    }
  }
}

function head(out: Buffer[], major: number, value: bigint): void {
  const mt = major << 5;
  if (value < 24n) {
    out.push(Buffer.from([mt | Number(value)]));
  } else if (value <= 0xffn) {
    out.push(Buffer.from([mt | 24, Number(value)]));
  } else if (value <= 0xffffn) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(Number(value), 1);
    out.push(b);
  } else if (value <= 0xffff_ffffn) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(Number(value), 1);
    out.push(b);
  } else {
    const b = Buffer.alloc(9);
    b[0] = mt | 27;
    b.writeBigUInt64BE(value, 1);
    out.push(b);
  }
}

// --- Decoder ----------------------------------------------------------------------------------

const utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function decode(data: Uint8Array): CborValue {
  if (data.length > MAX_INPUT_BYTES) throw new CborError('input too large');
  const reader = new Reader(data);
  const value = reader.read(0);
  if (reader.pos !== data.length) throw new CborError('trailing bytes');
  return value;
}

class Reader {
  pos = 0;
  private readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  read(depth: number): CborValue {
    if (depth > MAX_DEPTH) throw new CborError('nesting too deep');
    const initial = this.readByte();
    const major = initial >>> 5;
    const info = initial & 0x1f;
    switch (major) {
      case MAJOR_UINT:
        return { kind: 'uint', value: this.readArgument(info) };
      case MAJOR_BYTES:
        return { kind: 'bytes', value: this.readSlice(this.readLength(info)) };
      case MAJOR_TEXT: {
        const raw = this.readSlice(this.readLength(info));
        try {
          return { kind: 'text', value: utf8Decoder.decode(raw) };
        } catch {
          throw new CborError('invalid UTF-8 text');
        }
      }
      case MAJOR_ARRAY: {
        const count = this.readLength(info);
        const items: CborValue[] = [];
        for (let i = 0; i < count; i++) items.push(this.read(depth + 1));
        return { kind: 'array', items };
      }
      case MAJOR_MAP: {
        const count = this.readLength(info);
        const entries = new Map<number, CborValue>();
        let previousKey = -1n;
        for (let i = 0; i < count; i++) {
          const keyHead = this.readByte();
          if (keyHead >>> 5 !== MAJOR_UINT) throw new CborError('map keys must be uints');
          const key = this.readArgument(keyHead & 0x1f);
          if (key <= previousKey) throw new CborError('map keys not strictly ascending');
          if (key > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('map key too large');
          previousKey = key;
          entries.set(Number(key), this.read(depth + 1));
        }
        return { kind: 'map', entries };
      }
      default:
        throw new CborError(`unsupported major type ${major}`);
    }
  }

  private readByte(): number {
    if (this.pos >= this.data.length) throw new CborError('truncated input');
    return this.data[this.pos++]!;
  }

  private readArgument(info: number): bigint {
    if (info < 24) return BigInt(info);
    if (info === 24) return this.minimal(this.readBigEndian(1), 24n);
    if (info === 25) return this.minimal(this.readBigEndian(2), 0x100n);
    if (info === 26) return this.minimal(this.readBigEndian(4), 0x1_0000n);
    if (info === 27) {
      const v = this.readBigEndian(8);
      if (v > MAX_UINT63) throw new CborError('integer exceeds 63 bits');
      return this.minimal(v, 0x1_0000_0000n);
    }
    throw new CborError(`unsupported additional info ${info} (indefinite or reserved)`);
  }

  private minimal(value: bigint, min: bigint): bigint {
    if (value < min) throw new CborError('non-minimal integer encoding');
    return value;
  }

  /** Length of a string or container. Each element needs at least one byte, so we can bound it. */
  private readLength(info: number): number {
    const length = this.readArgument(info);
    if (length > BigInt(this.data.length - this.pos)) throw new CborError('length exceeds input');
    return Number(length);
  }

  private readSlice(length: number): Uint8Array {
    const slice = this.data.slice(this.pos, this.pos + length);
    this.pos += length;
    return slice;
  }

  private readBigEndian(count: number): bigint {
    let result = 0n;
    for (let i = 0; i < count; i++) result = (result << 8n) | BigInt(this.readByte());
    return result;
  }
}

// --- Typed access -----------------------------------------------------------------------------

/** Schema-checked view over a decoded map. Mirrors `CborMap` in Kotlin. */
export class CborMap {
  readonly entries: ReadonlyMap<number, CborValue>;

  constructor(entries: ReadonlyMap<number, CborValue>) {
    this.entries = entries;
  }

  /** Rejects maps that carry fields the schema does not define. */
  requireExactKeys(...keys: number[]): this {
    const actual = [...this.entries.keys()].sort((a, b) => a - b);
    const expected = [...new Set(keys)].sort((a, b) => a - b);
    if (actual.length !== expected.length || actual.some((k, i) => k !== expected[i])) {
      throw new CborError(`unexpected map keys [${actual}], expected [${expected}]`);
    }
    return this;
  }

  private field(key: number): CborValue {
    const v = this.entries.get(key);
    if (v === undefined) throw new CborError(`missing field ${key}`);
    return v;
  }

  uint(key: number): number {
    const v = this.field(key);
    if (v.kind !== 'uint') throw new CborError(`field ${key} is not a uint`);
    if (v.value > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError(`field ${key} is too large`);
    return Number(v.value);
  }

  bytes(key: number, size?: number): Buffer {
    const v = this.field(key);
    if (v.kind !== 'bytes') throw new CborError(`field ${key} is not bytes`);
    if (size !== undefined && v.value.length !== size) throw new CborError(`field ${key} must be ${size} bytes`);
    return Buffer.from(v.value);
  }

  text(key: number): string {
    const v = this.field(key);
    if (v.kind !== 'text') throw new CborError(`field ${key} is not text`);
    return v.value;
  }

  array(key: number): readonly CborValue[] {
    const v = this.field(key);
    if (v.kind !== 'array') throw new CborError(`field ${key} is not an array`);
    return v.items;
  }
}

export function asMap(value: CborValue): CborMap {
  if (value.kind !== 'map') throw new CborError('expected map');
  return new CborMap(value.entries);
}

export function asBytes(value: CborValue): Buffer {
  if (value.kind !== 'bytes') throw new CborError('expected bytes');
  return Buffer.from(value.value);
}
