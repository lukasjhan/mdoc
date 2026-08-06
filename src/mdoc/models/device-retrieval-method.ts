import { z } from 'zod'
import { buildStructure, type CborDecodeOptions, CborStructure, cborArray, decodeBytes, fromEncoded } from '../../cbor'
import { CborEncodeError } from '../../cbor/error'
import { BleOptions } from './ble-options'
import { NfcOptions } from './nfc-options'
import type { RetrievalOptions, RetrievalOptionsStructure } from './retrieval-options'
import { WifiOptions } from './wifi-options'

export enum DeviceRetrievalMethodType {
  Nfc = 1,
  Ble = 2,
  WifiAware = 3,
}

/**
 * Which class position 2 holds depends on position 0, which a per-position
 * schema cannot see. The options are therefore instantiated before validation,
 * in `fromEncodedStructure`, and this codec only carries them back out.
 */
const retrievalOptions = z.codec(
  z.unknown(),
  z.custom<RetrievalOptions>((value) => value instanceof CborStructure),
  {
    decode: (encoded) => encoded as RetrievalOptions,
    encode: (options) => options.encodedStructure(),
  }
)

const schema = cborArray([
  ['type', z.number()],
  ['version', z.number()],
  ['retrievalOptions', retrievalOptions],
])

export type DeviceRetrievalMethodStructure = [DeviceRetrievalMethodType, number, RetrievalOptionsStructure]

export type DeviceRetrievalMethodOptions = {
  type: DeviceRetrievalMethodType | number
  version: number
  retrievalOptions: RetrievalOptions
}

const optionsClassFor = (type: unknown) => {
  if (type === DeviceRetrievalMethodType.Nfc) return NfcOptions
  if (type === DeviceRetrievalMethodType.Ble) return BleOptions
  if (type === DeviceRetrievalMethodType.WifiAware) return WifiOptions

  throw new CborEncodeError(`Type '${type}' does not match a valid device retrieval type`)
}

export class DeviceRetrievalMethod extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceRetrievalMethodOptions) {
    super(
      buildStructure([
        ['type', options.type],
        ['version', options.version],
        ['retrievalOptions', options.retrievalOptions],
      ])
    )
  }

  public get type(): DeviceRetrievalMethodType {
    return this.structure.get('type') as DeviceRetrievalMethodType
  }

  public get version(): number {
    return this.structure.get('version') as number
  }

  public get retrievalOptions(): RetrievalOptions {
    return this.structure.get('retrievalOptions') as RetrievalOptions
  }

  public override encodedStructure(): DeviceRetrievalMethodStructure {
    return super.encodedStructure() as DeviceRetrievalMethodStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): DeviceRetrievalMethod {
    if (!Array.isArray(encodedStructure)) {
      throw new CborEncodeError('A device retrieval method must be an array')
    }

    const [type, version, options] = encodedStructure
    const instantiated = optionsClassFor(type).fromEncodedStructure(options) as RetrievalOptions

    return fromEncoded(DeviceRetrievalMethod, [type, version, instantiated])
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceRetrievalMethod {
    return decodeBytes(DeviceRetrievalMethod, bytes, options)
  }
}
