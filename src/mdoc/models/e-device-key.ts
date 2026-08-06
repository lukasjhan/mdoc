import { type CborDecodeOptions, decodeBytes, fromEncoded } from '../../cbor'
import { assertKeyType, CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type EDeviceKeyStructure = EncodedCoseKeyStructure

export type EDeviceKeyOptions = CoseKeyOptions

export class EDeviceKey extends CoseKey {
  public static override fromEncodedStructure(encodedStructure: unknown): EDeviceKey {
    assertKeyType(encodedStructure)

    return fromEncoded(EDeviceKey, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): EDeviceKey {
    return decodeBytes(EDeviceKey, bytes, options)
  }
}
