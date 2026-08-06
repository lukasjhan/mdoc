import { z } from 'zod'
import { buildStructure, CborStructure, cborArray } from '../../cbor'

const schema = cborArray([
  ['origin', z.string()],
  ['nonce', z.string()],
  ['jwkThumbprint', z.union([z.instanceof(Uint8Array), z.null()])],
])

export type Oid4vpDcApiHandoverInfoStructure = [string, string, Uint8Array | null]

export type Oid4vpDcApiHandoverInfoOptions = {
  origin: string
  nonce: string
  jwkThumbprint?: Uint8Array
}

export class Oid4vpDcApiHandoverInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: Oid4vpDcApiHandoverInfoOptions) {
    super(
      buildStructure([
        ['origin', options.origin],
        ['nonce', options.nonce],
        ['jwkThumbprint', options.jwkThumbprint ?? null],
      ])
    )
  }

  public get origin(): string {
    return this.structure.get('origin') as string
  }

  public get nonce(): string {
    return this.structure.get('nonce') as string
  }

  public get jwkThumbprint(): Uint8Array | undefined {
    return (this.structure.get('jwkThumbprint') as Uint8Array | null) ?? undefined
  }

  public override encodedStructure(): Oid4vpDcApiHandoverInfoStructure {
    return super.encodedStructure() as Oid4vpDcApiHandoverInfoStructure
  }
}
