import { type CborDecodeOptions, decodeBytes, fromEncoded } from '../../cbor'
import { Sign1, type Sign1Structure } from '../../cose/sign1'

export type DeviceSignatureStructure = Sign1Structure

export class DeviceSignature extends Sign1 {
  public static override fromEncodedStructure(encodedStructure: unknown): DeviceSignature {
    return fromEncoded(DeviceSignature, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceSignature {
    return decodeBytes(DeviceSignature, bytes, options)
  }
}
