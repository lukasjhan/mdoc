import { z } from 'zod'
import {
  type CborDecodeOptions,
  CborStructure,
  cborDynamicMap,
  cborStructure,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import { ErrorItems } from './error-items'
import type { Namespace } from './namespace'

const schema = cborDynamicMap(z.string(), cborStructure(ErrorItems))

export type ErrorsOptions = {
  errors: Map<Namespace, ErrorItems>
}

export class Errors extends CborStructure {
  public static override schema = schema

  public constructor(options: ErrorsOptions) {
    super(new Map(options.errors))
  }

  public get errors(): Map<Namespace, ErrorItems> {
    return this.structure as Map<Namespace, ErrorItems>
  }

  public static override fromEncodedStructure(encodedStructure: unknown): Errors {
    return fromEncoded(Errors, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Errors {
    return decodeBytes(Errors, bytes, options)
  }
}
