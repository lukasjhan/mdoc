import { z } from 'zod'
import { buildStructure, CborStructure, cborMap } from '../../cbor'

const schema = cborMap([
  ['status', z.number().optional()],
  ['data', z.instanceof(Uint8Array).optional()],
])

export type SessionDataStructure = {
  status?: number
  data?: Uint8Array
}

export type SessionDataOptions = {
  status?: number
  data?: Uint8Array
}

export class SessionData extends CborStructure {
  public static override schema = schema

  public constructor(options: SessionDataOptions) {
    super(
      buildStructure([
        ['status', options.status],
        ['data', options.data],
      ])
    )
  }

  public get status(): number | undefined {
    return this.structure.get('status') as number | undefined
  }

  public get data(): Uint8Array | undefined {
    return this.structure.get('data') as Uint8Array | undefined
  }

  public override encodedStructure(): SessionDataStructure {
    return super.encodedStructure() as SessionDataStructure
  }
}
