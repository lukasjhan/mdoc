import {
  type CborDecodeOptions,
  type CborEncodeOptions,
  cborEncode,
  DataItem,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import { assertKeyType, CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type EReaderKeyStructure = EncodedCoseKeyStructure

export type EReaderKeyOptions = CoseKeyOptions

export class EReaderKey extends CoseKey {
  /**
   * Original CBOR bytes, kept when decoding so that encode() reproduces them.
   * A plain property rather than a private field: decoded structures are built
   * without running the constructor, which never installs private fields.
   */
  protected rawBytes?: Uint8Array

  public override encode(options?: CborEncodeOptions): Uint8Array {
    if (this.rawBytes) {
      if (options?.asDataItem) {
        return cborEncode(new DataItem({ buffer: this.rawBytes }))
      }
      return this.rawBytes
    }
    return super.encode(options)
  }

  public static override fromEncodedStructure(encodedStructure: unknown): EReaderKey {
    assertKeyType(encodedStructure)

    return fromEncoded(EReaderKey, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): EReaderKey {
    const key = decodeBytes(EReaderKey, bytes, options)
    key.rawBytes = bytes
    return key
  }
}
