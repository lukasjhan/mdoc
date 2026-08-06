import { z } from 'zod'
import {
  type CborDecodeOptions,
  type CborMap,
  CborStructure,
  cborDynamicMap,
  decodeBytes,
  fromEncoded,
} from '../../cbor/index.js'
import type { Header } from './defaults.js'

export type UnprotectedHeadersStructure = Map<Header | unknown, unknown>

export type UnprotectedHeadersOptions = {
  unprotectedHeaders?: Map<Header | unknown, unknown>
}

// The unprotected bucket is not covered by any signature and carries whatever
// labels an implementation chooses, so entries pass through unconstrained.
const schema = cborDynamicMap(z.unknown(), z.unknown())

export class UnprotectedHeaders extends CborStructure {
  public static override schema = schema

  public constructor(options: UnprotectedHeadersOptions = {}) {
    super(new Map(options.unprotectedHeaders) as CborMap)
  }

  public get headers(): Map<Header | unknown, unknown> {
    return this.structure
  }

  public override encodedStructure(): UnprotectedHeadersStructure {
    return super.encodedStructure() as UnprotectedHeadersStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): UnprotectedHeaders {
    return fromEncoded(UnprotectedHeaders, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): UnprotectedHeaders {
    return decodeBytes(UnprotectedHeaders, bytes, options)
  }
}
