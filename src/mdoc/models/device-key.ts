import { type CborDecodeOptions, decodeBytes, fromEncoded } from '../../cbor'
import { assertKeyType, CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type DeviceKeyStructure = EncodedCoseKeyStructure

export type DeviceKeyOptions = CoseKeyOptions

export class DeviceKey extends CoseKey {
  public static override fromEncodedStructure(encodedStructure: unknown): DeviceKey {
    assertKeyType(encodedStructure)

    return fromEncoded(DeviceKey, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceKey {
    return decodeBytes(DeviceKey, bytes, options)
  }
}
