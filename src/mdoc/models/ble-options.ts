import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborMap,
  coerceNumericKeys,
  decodeBytes,
  fromEncoded,
} from '../../cbor'

// ISO 18013-5 keys these by unsigned integer. The previous encoder built a
// plain object, whose keys CBOR writes as text strings.
const schema = cborMap([
  [0, z.boolean()],
  [1, z.boolean()],
  [10, z.instanceof(Uint8Array).optional()],
  [11, z.instanceof(Uint8Array).optional()],
  [20, z.instanceof(Uint8Array).optional()],
])

export type BleOptionsStructure = {
  0: boolean
  1: boolean
  10?: Uint8Array
  11?: Uint8Array
  20?: Uint8Array
}

export type BleOptionsOptions = {
  peripheralServerMode: boolean
  centralClientMode: boolean
  peripheralServerModeUuid?: Uint8Array
  centralClientModeUuid?: Uint8Array
  peripheralServerModeDeviceAddress?: Uint8Array
}

export class BleOptions extends CborStructure {
  public static override schema = schema

  public constructor(options: BleOptionsOptions) {
    super(
      buildStructure([
        [0, options.peripheralServerMode],
        [1, options.centralClientMode],
        [10, options.peripheralServerModeUuid],
        [11, options.centralClientModeUuid],
        [20, options.peripheralServerModeDeviceAddress],
      ])
    )
  }

  public get peripheralServerMode(): boolean {
    return this.structure.get(0) as boolean
  }

  public get centralClientMode(): boolean {
    return this.structure.get(1) as boolean
  }

  public get peripheralServerModeUuid(): Uint8Array | undefined {
    return this.structure.get(10) as Uint8Array | undefined
  }

  public get centralClientModeUuid(): Uint8Array | undefined {
    return this.structure.get(11) as Uint8Array | undefined
  }

  public get peripheralServerModeDeviceAddress(): Uint8Array | undefined {
    return this.structure.get(20) as Uint8Array | undefined
  }

  public override encodedStructure(): BleOptionsStructure {
    return super.encodedStructure() as unknown as BleOptionsStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): BleOptions {
    return fromEncoded(BleOptions, coerceNumericKeys(encodedStructure))
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): BleOptions {
    return decodeBytes(BleOptions, bytes, options)
  }
}
