import { z } from 'zod'
import {
  buildStructure,
  CborStructure,
  cborMap,
  coerceNumericKeys,
  fromEncoded,
  type SchemaBackedClass,
} from '../../cbor'

// ISO/IEC 18013-5:2021 8.2.2.3:
//
//   WifiOptions = {
//     ? 0: tstr,  ; Pass-phrase Info Pass-phrase
//     ? 1: uint,  ; Channel Info Operating Class
//     ? 2: uint,  ; Channel Info Channel Number
//     ? 3: bstr   ; Band Info Supported Bands
//   }
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
        [1, options.channelInfoOperatingClass],
        [2, options.channelInfoChannelNumber],
        [3, options.bandInfoSupportedBands],
      ])
    )
  }

  public get passPhrase(): string | undefined {
    return this.structure.get(0) as string | undefined
  }

  public get channelInfoOperatingClass(): number | undefined {
    return this.structure.get(1) as number | undefined
  }

  public get channelInfoChannelNumber(): number | undefined {
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
