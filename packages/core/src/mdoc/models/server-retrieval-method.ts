import { buildStructure, CborStructure, cborMap, cborStructure } from '../../cbor'
import { Oidc, type OidcStructure } from './oidc'
import { WebApi, type WebApiStructure } from './web-api'

const schema = cborMap([
  ['webApi', cborStructure(WebApi).optional()],
  ['oidc', cborStructure(Oidc).optional()],
])

export type ServerRetrievalMethodStructure = {
  webApi?: WebApiStructure
  oidc?: OidcStructure
}

export type ServerRetrievalMethodOptions = {
  webApi?: WebApi
  oidc?: Oidc
}

export class ServerRetrievalMethod extends CborStructure {
  public static override schema = schema

  public constructor(options: ServerRetrievalMethodOptions) {
    super(
      buildStructure([
        ['webApi', options.webApi],
        ['oidc', options.oidc],
      ])
    )
  }

  public get webApi(): WebApi | undefined {
    return this.structure.get('webApi') as WebApi | undefined
  }

  public get oidc(): Oidc | undefined {
    return this.structure.get('oidc') as Oidc | undefined
  }

  public override encodedStructure(): ServerRetrievalMethodStructure {
    return super.encodedStructure() as ServerRetrievalMethodStructure
  }
}
