import { z } from 'zod'
import { buildStructure, CborStructure, cborArray } from '../../cbor'

const schema = cborArray([
  ['clientId', z.string()],
  ['nonce', z.string()],
  ['jwkThumbprint', z.union([z.instanceof(Uint8Array), z.null()])],
  ['responseUri', z.string()],
])

export type Oid4vpHandoverInfoStructure = [string, string, Uint8Array | null, string]

export type Oid4vpHandoverInfoOptions = {
  clientId: string
  nonce: string
  jwkThumbprint?: Uint8Array
  responseUri: string
}

export class Oid4vpHandoverInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: Oid4vpHandoverInfoOptions) {
    super(
      buildStructure([
        ['clientId', options.clientId],
        ['nonce', options.nonce],
        ['jwkThumbprint', options.jwkThumbprint ?? null],
        ['responseUri', options.responseUri],
      ])
    )
  }

  public get clientId(): string {
    return this.structure.get('clientId') as string
  }

  public get nonce(): string {
    return this.structure.get('nonce') as string
  }

  public get jwkThumbprint(): Uint8Array | undefined {
    return (this.structure.get('jwkThumbprint') as Uint8Array | null) ?? undefined
  }

  public get responseUri(): string {
    return this.structure.get('responseUri') as string
  }

  public override encodedStructure(): Oid4vpHandoverInfoStructure {
    return super.encodedStructure() as Oid4vpHandoverInfoStructure
  }
}
