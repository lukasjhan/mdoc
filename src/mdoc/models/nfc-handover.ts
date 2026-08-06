import { z } from 'zod'
import { buildStructure, cborArray } from '../../cbor'
import { Handover } from './handover'

const schema = cborArray([
  ['selectMessage', z.instanceof(Uint8Array)],
  ['requestMessage', z.union([z.instanceof(Uint8Array), z.null()])],
])

export type NfcHandoverStructure = [Uint8Array, Uint8Array | null]

export type NfcHandoverOptions = {
  selectMessage: Uint8Array
  requestMessage?: Uint8Array
}

export class NfcHandover extends Handover {
  public static override schema = schema

  public constructor(options: NfcHandoverOptions) {
    super(
      buildStructure([
        ['selectMessage', options.selectMessage],
        ['requestMessage', options.requestMessage ?? null],
      ])
    )
  }

  public get selectMessage(): Uint8Array {
    return this.structure.get('selectMessage') as Uint8Array
  }

  public get requestMessage(): Uint8Array | undefined {
    return (this.structure.get('requestMessage') as Uint8Array | null) ?? undefined
  }

  public override encodedStructure(): NfcHandoverStructure {
    return super.encodedStructure() as NfcHandoverStructure
  }

  public static override isCorrectHandover(structure: unknown): structure is NfcHandoverStructure {
    return (
      Array.isArray(structure) &&
      structure[0] instanceof Uint8Array &&
      (structure[1] instanceof Uint8Array || structure[1] === null)
    )
  }
}
