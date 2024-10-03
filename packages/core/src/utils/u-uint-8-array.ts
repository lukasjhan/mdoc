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
