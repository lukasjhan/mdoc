import {
  type CborDecodeOptions,
  type CborEncodeOptions,
  type CborStructure,
  cborEncode,
  DataItem,
  decodeBytes,
  type SchemaBackedClass,
} from '../../cbor'
import { CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

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

  public static override decode<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    bytes: Uint8Array,
    options?: CborDecodeOptions
  ): T {
    const key = decodeBytes(this, bytes, options)
    ;(key as { rawBytes?: Uint8Array }).rawBytes = bytes
    return key
  }
}
