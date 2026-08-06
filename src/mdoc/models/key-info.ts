import { z } from 'zod'
import { CborStructure, cborDynamicMap } from '../../cbor'

const schema = cborDynamicMap(z.number(), z.unknown())

export type KeyInfoStructure = Map<number, unknown>

export type KeyInfoOptions = {
  keyInfo: Map<number, unknown>
}

export class KeyInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: KeyInfoOptions) {
    super(new Map(options.keyInfo))
  }

  public get keyInfo(): Map<number, unknown> {
    return this.structure as Map<number, unknown>
  }

  public override encodedStructure(): KeyInfoStructure {
    return super.encodedStructure() as KeyInfoStructure
  }
}
