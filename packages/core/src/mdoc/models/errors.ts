import { z } from 'zod'
import { CborStructure, cborDynamicMap, cborStructure } from '../../cbor'
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
}
