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
  [0, z.number()],
  [1, z.number()],
])

export type NfcOptionsStructure = {
  0: number
  1: number
}

export type NfcOptionsOptions = {
  maxLenCommandDataField: number
  maxLenResponseDataField: number
}

export class NfcOptions extends CborStructure {
  public static override schema = schema

  public constructor(options: NfcOptionsOptions) {
    super(
      buildStructure([
        [0, options.maxLenCommandDataField],
        [1, options.maxLenResponseDataField],
      ])
    )
  }

  public get maxLenCommandDataField(): number {
    return this.structure.get(0) as number
  }

  public get maxLenResponseDataField(): number {
    return this.structure.get(1) as number
  }

  public override encodedStructure(): NfcOptionsStructure {
    return super.encodedStructure() as unknown as NfcOptionsStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): NfcOptions {
    return fromEncoded(NfcOptions, coerceNumericKeys(encodedStructure))
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): NfcOptions {
    return decodeBytes(NfcOptions, bytes, options)
  }
}
