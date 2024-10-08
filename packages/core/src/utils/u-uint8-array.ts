/**
 * Decodes the `input` and returns a string. If `options.stream` is `true`, any
 * incomplete byte sequences occurring at the end of the `input` are buffered
 * internally and emitted after the next call to `textDecoder.decode()`.
 *
 * If `textDecoder.fatal` is `true`, decoding errors that occur will result in a `TypeError` being thrown.
 * @param input An `ArrayBuffer`, `DataView`, or `TypedArray` instance containing the encoded data.
 */
export function uint8ArrayToString(input: Uint8Array): string {
  return String.fromCharCode.apply(null, Array.from(input));
}

/**
 * UTF-8 encodes the `input` string and returns a `Uint8Array` containing the
 * encoded bytes.
 * @param [input='an empty string'] The text to encode.
 */
export function stringToUint8Array(input: string): Uint8Array {
  const buffer = new ArrayBuffer(input.length);
  const uint8Array = new Uint8Array(buffer);
  for (let i = 0; i < input.length; i++) {
    uint8Array[i] = input.charCodeAt(i);
  }
  return uint8Array;
}

export function concatUint8Array(...buffers: Uint8Array[]): Uint8Array {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  buffers.forEach(buffer => {
    buf.set(buffer, i);
    i += buffer.length;
  });
  return buf;
}

export function areEqualUint8Array(
  buf1: Uint8Array,
  buf2: Uint8Array
): boolean {
  if (buf1 === buf2) {
    return true;
  }

  if (buf1.byteLength !== buf2.byteLength) {
    return false;
  }

  for (let i = 0; i < buf1.byteLength; i++) {
    if (buf1[i] !== buf2[i]) {
      return false;
    }
  }

  return true;
}
