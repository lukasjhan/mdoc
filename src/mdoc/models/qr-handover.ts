import type { CborStructure, SchemaBackedClass } from '../../cbor'
import { Handover } from './handover'

export type QrHandoverStructure = null

export class QrHandover extends Handover {
  public encodedStructure(): QrHandoverStructure {
    return null
  }

  public static override fromEncodedStructure<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    _encodedStructure: unknown
  ): T {
    return new QrHandover() as unknown as T
  }

  public static isCorrectHandover(structure: unknown): structure is QrHandoverStructure {
    return structure === null
  }
}
