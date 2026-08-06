import { z } from 'zod'
import { type CborDecodeOptions, CborStructure, cborDynamicMap, decodeBytes, fromEncoded } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { ErrorCode } from './error-code'

const schema = cborDynamicMap(z.string(), z.number())

export type ErrorItemsStructure = Map<DataElementIdentifier, ErrorCode>

export type ErrorItemsOptions = {
  errorItems: Map<DataElementIdentifier, ErrorCode>
}

export class ErrorItems extends CborStructure {
  public static override schema = schema

  public constructor(options: ErrorItemsOptions) {
    super(new Map(options.errorItems))
  }

  public get errorItems(): Map<DataElementIdentifier, ErrorCode> {
    return this.structure as Map<DataElementIdentifier, ErrorCode>
  }

  public override encodedStructure(): ErrorItemsStructure {
    return super.encodedStructure() as ErrorItemsStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): ErrorItems {
    return fromEncoded(ErrorItems, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ErrorItems {
    return decodeBytes(ErrorItems, bytes, options)
  }
}
