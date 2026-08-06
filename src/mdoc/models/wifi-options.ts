import { z } from 'zod'
import {
  buildStructure,
  CborStructure,
  cborMap,
  coerceNumericKeys,
  fromEncoded,
  type SchemaBackedClass,
} from '../../cbor'

// ISO 18013-5 keys these by unsigned integer. The previous encoder built a
// plain object, whose keys CBOR writes as text strings.
//
// NOTE: key 1 holds the channel number and key 2 the operating class here,
// which is the mapping this library has always used in both directions. It
// looks inverted relative to ISO 18013-5 Table 13; left as-is because changing
// it would alter the wire format on a reading of the spec that has not been
// confirmed against the text.
const schema = cborMap([
  [0, z.string().optional()],
  [1, z.number().optional()],
  [2, z.number().optional()],
  [3, z.instanceof(Uint8Array).optional()],
])

export type WifiOptionsStructure = {
  0?: string
  1?: number
  2?: number
  3?: Uint8Array
}

export type WifiOptionsOptions = {
  passPhrase?: string
  channelInfoOperatingClass?: number
  channelInfoChannelNumber?: number
  bandInfoSupportedBands?: Uint8Array
}

export class WifiOptions extends CborStructure {
  public static override schema = schema

  public constructor(options: WifiOptionsOptions) {
    super(
      buildStructure([
        [0, options.passPhrase],
        [1, options.channelInfoChannelNumber],
        [2, options.channelInfoOperatingClass],
        [3, options.bandInfoSupportedBands],
      ])
    )
  }

  public get passPhrase(): string | undefined {
    return this.structure.get(0) as string | undefined
  }

  public get channelInfoChannelNumber(): number | undefined {
    return this.structure.get(1) as number | undefined
  }

  public get channelInfoOperatingClass(): number | undefined {
    return this.structure.get(2) as number | undefined
  }

  public get bandInfoSupportedBands(): Uint8Array | undefined {
    return this.structure.get(3) as Uint8Array | undefined
  }

  public override encodedStructure(): WifiOptionsStructure {
    return super.encodedStructure() as unknown as WifiOptionsStructure
  }

  public static override fromEncodedStructure<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    encodedStructure: unknown
  ): T {
    return fromEncoded(this, coerceNumericKeys(encodedStructure))
  }
}
