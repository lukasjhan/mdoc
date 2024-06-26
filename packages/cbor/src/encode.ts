export type TextEncoder = (data: string) => Uint8Array;

export class CBOREncoder {
  private textEncoder: TextEncoder;
  constructor(textEncoder: TextEncoder) {
    this.textEncoder = textEncoder;
  }

  public encode(value: unknown): Uint8Array {
    if (value === null) return this.encodeNull(value);
    if (typeof value === 'undefined') return this.encodeUndefined(value);
    if (typeof value === 'boolean') return this.encodeBoolean(value);
    if (typeof value === 'number') return this.encodeNumber(value);
    if (typeof value === 'string') return this.encodeString(value);
    if (Array.isArray(value)) return this.encodeArray(value);
    if (value instanceof Uint8Array) return this.encodeByteString(value);
    if (value instanceof ArrayBuffer)
      return this.encodeByteString(new Uint8Array(value));

    if (typeof value === 'object')
      return this.encodeObject(value as Record<string, unknown>);

    throw new Error('Unsupported type');
  }

  private encodeNull(value: null) {
    return new Uint8Array([0xf6]);
  }

  private encodeUndefined(value: undefined) {
    return new Uint8Array([0xf7]);
  }

  private encodeBoolean(value: boolean) {
    return new Uint8Array([value ? 0xf5 : 0xf4]);
  }

  private encodeNumber(value: number) {
    if (Number.isInteger(value)) {
      if (value >= 0) {
        if (value <= 0x17) {
          return new Uint8Array([value]);
        } else if (value <= 0xff) {
          return new Uint8Array([0x18, value]);
        } else if (value <= 0xffff) {
          return new Uint8Array([0x19, value >> 8, value & 0xff]);
        } else if (value <= 0xffffffff) {
          return new Uint8Array([
            0x1a,
            value >> 24,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff,
          ]);
        } else {
          return new Uint8Array([
            0x1b,
            value >> 56,
            (value >> 48) & 0xff,
            (value >> 40) & 0xff,
            (value >> 32) & 0xff,
            (value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff,
          ]);
        }
      } else {
        const absValue = Math.abs(value + 1);
        if (absValue <= 0x17) {
          return new Uint8Array([0x20 + absValue]);
        } else if (absValue <= 0xff) {
          return new Uint8Array([0x38, absValue]);
        } else if (absValue <= 0xffff) {
          return new Uint8Array([0x39, absValue >> 8, absValue & 0xff]);
        } else if (absValue <= 0xffffffff) {
          return new Uint8Array([
            0x3a,
            absValue >> 24,
            (absValue >> 16) & 0xff,
            (absValue >> 8) & 0xff,
            absValue & 0xff,
          ]);
        } else {
          return new Uint8Array([
            0x3b,
            absValue >> 56,
            (absValue >> 48) & 0xff,
            (absValue >> 40) & 0xff,
            (absValue >> 32) & 0xff,
            (absValue >> 24) & 0xff,
            (absValue >> 16) & 0xff,
            (absValue >> 8) & 0xff,
            absValue & 0xff,
          ]);
        }
      }
    } else {
      const floatArray = new Float64Array([value]);
      const uint8Array = new Uint8Array(floatArray.buffer);

      if (value === 0) {
        // ±0
        const sign = 1 / value < 0 ? 0xf9 : 0xf9;
        return new Uint8Array([sign, 0x00, 0x00]);
      } else if (!isFinite(value)) {
        // NaN, Infinity
        const sign = value < 0 ? 0xf9 : 0xf9;
        return new Uint8Array([sign, 0x7e, 0x00]);
      } else {
        const result = new Uint8Array(9);
        result[0] = 0xfb;
        for (let i = 0; i < 8; i++) {
          result[i + 1] = uint8Array[7 - i];
        }
        return result;
      }
    }
  }

  private encodeString(value: string) {
    const utf8Data = this.textEncoder(value);
    const length = utf8Data.length;
    let header: Uint8Array;

    if (length <= 0x17) {
      header = new Uint8Array([0x60 + length]);
    } else if (length <= 0xff) {
      header = new Uint8Array([0x78, length]);
    } else if (length <= 0xffff) {
      header = new Uint8Array([0x79, length >> 8, length & 0xff]);
    } else if (length <= 0xffffffff) {
      header = new Uint8Array([
        0x7a,
        length >> 24,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    } else {
      header = new Uint8Array([
        0x7b,
        length >> 56,
        (length >> 48) & 0xff,
        (length >> 40) & 0xff,
        (length >> 32) & 0xff,
        (length >> 24) & 0xff,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    }

    const result = new Uint8Array(header.length + utf8Data.length);
    result.set(header);
    result.set(utf8Data, header.length);
    return result;
  }

  private encodeArray(value: unknown[]) {
    const length = value.length;
    let header: Uint8Array;

    if (length <= 0x17) {
      header = new Uint8Array([0x80 + length]);
    } else if (length <= 0xff) {
      header = new Uint8Array([0x98, length]);
    } else if (length <= 0xffff) {
      header = new Uint8Array([0x99, length >> 8, length & 0xff]);
    } else if (length <= 0xffffffff) {
      header = new Uint8Array([
        0x9a,
        length >> 24,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    } else {
      header = new Uint8Array([
        0x9b,
        length >> 56,
        (length >> 48) & 0xff,
        (length >> 40) & 0xff,
        (length >> 32) & 0xff,
        (length >> 24) & 0xff,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    }

    const itemsData = value.map((item) => this.encode(item));
    const itemsLength = itemsData.reduce((sum, item) => sum + item.length, 0);
    const result = new Uint8Array(header.length + itemsLength);
    result.set(header);
    let offset = header.length;
    for (const item of itemsData) {
      result.set(item, offset);
      offset += item.length;
    }
    return result;
  }

  private encodeObject(value: Record<string, unknown>) {
    const keys = Object.keys(value);
    const length = keys.length;
    let header: Uint8Array;

    if (length <= 0x17) {
      header = new Uint8Array([0xa0 + length]);
    } else if (length <= 0xff) {
      header = new Uint8Array([0xb8, length]);
    } else if (length <= 0xffff) {
      header = new Uint8Array([0xb9, length >> 8, length & 0xff]);
    } else if (length <= 0xffffffff) {
      header = new Uint8Array([
        0xba,
        length >> 24,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    } else {
      header = new Uint8Array([
        0xbb,
        length >> 56,
        (length >> 48) & 0xff,
        (length >> 40) & 0xff,
        (length >> 32) & 0xff,
        (length >> 24) & 0xff,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    }

    const itemsData: Uint8Array[] = [];
    for (const key of keys) {
      const keyData = this.encode(key);
      const valueData = this.encode(value[key]);
      itemsData.push(keyData, valueData);
    }

    const itemsLength = itemsData.reduce((sum, item) => sum + item.length, 0);
    const result = new Uint8Array(header.length + itemsLength);
    result.set(header);

    let offset = header.length;
    for (const item of itemsData) {
      result.set(item, offset);
      offset += item.length;
    }

    return result;
  }

  private encodeByteString(value: Uint8Array) {
    const length = value.length;
    let header: Uint8Array;

    if (length <= 0x17) {
      header = new Uint8Array([0x40 + length]);
    } else if (length <= 0xff) {
      header = new Uint8Array([0x58, length]);
    } else if (length <= 0xffff) {
      header = new Uint8Array([0x59, length >> 8, length & 0xff]);
    } else if (length <= 0xffffffff) {
      header = new Uint8Array([
        0x5a,
        length >> 24,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    } else {
      header = new Uint8Array([
        0x5b,
        length >> 56,
        (length >> 48) & 0xff,
        (length >> 40) & 0xff,
        (length >> 32) & 0xff,
        (length >> 24) & 0xff,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    }

    const result = new Uint8Array(header.length + value.length);
    result.set(header);
    result.set(value, header.length);
    return result;
  }
}
