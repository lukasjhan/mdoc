import { z } from 'zod'
import { buildStructure, CborStructure, cborArray } from '../../cbor'

const schema = cborArray([
  ['version', z.number()],
  ['issuerUrl', z.string()],
  ['serverRetrievalToken', z.string()],
])

export type WebApiStructure = [number, string, string]

export type WebApiOptions = {
  version: number
  issuerUrl: string
  serverRetrievalToken: string
}

export class WebApi extends CborStructure {
  public static override schema = schema

  public constructor(options: WebApiOptions) {
    super(
      buildStructure([
        ['version', options.version],
        ['issuerUrl', options.issuerUrl],
        ['serverRetrievalToken', options.serverRetrievalToken],
      ])
    )
  }

  public get version(): number {
    return this.structure.get('version') as number
  }

  public get issuerUrl(): string {
    return this.structure.get('issuerUrl') as string
  }

  public get serverRetrievalToken(): string {
    return this.structure.get('serverRetrievalToken') as string
  }

  public override encodedStructure(): WebApiStructure {
    return super.encodedStructure() as WebApiStructure
  }
}
