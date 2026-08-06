import { z } from 'zod'
import { CborStructure, cborDynamicMap } from '../../cbor'
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
}
