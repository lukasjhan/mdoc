import { z } from 'zod'
import { buildStructure, CborStructure, cborArray } from '../../cbor'

const schema = cborArray([
  ['origin', z.string()],
  ['clientId', z.string()],
  ['nonce', z.string()],
])

export type Oid4vpDcApiDraft24HandoverInfoStructure = [string, string, string]

export type Oid4vpDcApiDraft24HandoverInfoOptions = {
  origin: string
  clientId: string
  nonce: string
}

export class Oid4vpDcApiDraft24HandoverInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: Oid4vpDcApiDraft24HandoverInfoOptions) {
    super(
      buildStructure([
        ['origin', options.origin],
        ['clientId', options.clientId],
        ['nonce', options.nonce],
      ])
    )
  }

  public get origin(): string {
    return this.structure.get('origin') as string
  }

  public get clientId(): string {
    return this.structure.get('clientId') as string
  }

  public get nonce(): string {
    return this.structure.get('nonce') as string
  }

  public override encodedStructure(): Oid4vpDcApiDraft24HandoverInfoStructure {
    return super.encodedStructure() as Oid4vpDcApiDraft24HandoverInfoStructure
  }
}
