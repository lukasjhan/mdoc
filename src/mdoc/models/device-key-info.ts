import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborMap,
  cborStructure,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import { DeviceKey } from './device-key'
import { KeyAuthorizations } from './key-authorizations'
import { KeyInfo } from './key-info'

const schema = cborMap([
  ['deviceKey', cborStructure(DeviceKey)],
  ['keyAuthorizations', cborStructure(KeyAuthorizations).optional()],
  ['keyInfo', cborStructure(KeyInfo).optional()],
])

export type DeviceKeyInfoOptions = {
  deviceKey: DeviceKey
  keyAuthorizations?: KeyAuthorizations
  keyInfo?: KeyInfo
}

export class DeviceKeyInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceKeyInfoOptions) {
    super(
      buildStructure([
        ['deviceKey', options.deviceKey],
        ['keyInfo', options.keyInfo],
        ['keyAuthorizations', options.keyAuthorizations],
      ])
    )
  }

  public get deviceKey(): DeviceKey {
    return this.structure.get('deviceKey') as DeviceKey
  }

  public get keyAuthorizations(): KeyAuthorizations | undefined {
    return this.structure.get('keyAuthorizations') as KeyAuthorizations | undefined
  }

  public get keyInfo(): KeyInfo | undefined {
    return this.structure.get('keyInfo') as KeyInfo | undefined
  }

  public static override fromEncodedStructure(encodedStructure: unknown): DeviceKeyInfo {
    return fromEncoded(DeviceKeyInfo, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceKeyInfo {
    return decodeBytes(DeviceKeyInfo, bytes, options)
  }
}
