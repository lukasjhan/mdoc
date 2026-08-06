import { z } from 'zod'
import { buildStructure, CborStructure, cborMap } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { Namespace } from './namespace'

const schema = cborMap([
  ['nameSpaces', z.array(z.string()).optional()],
  ['dataElements', z.map(z.string(), z.array(z.string())).optional()],
])

export type KeyAuthorizationsStructure = {
  nameSpaces?: Array<Namespace>
  dataElements?: Map<Namespace, Array<DataElementIdentifier>>
}

export type KeyAuthorizationsOptions = {
  namespaces?: Array<Namespace>
  dataElements?: Map<Namespace, Array<DataElementIdentifier>>
}

export class KeyAuthorizations extends CborStructure {
  public static override schema = schema

  public constructor(options: KeyAuthorizationsOptions) {
    // Absent members are left out rather than written as CBOR undefined, which
    // is what the previous hand-written encoder emitted for `? nameSpaces` and
    // `? dataElements`.
    super(
      buildStructure([
        ['nameSpaces', options.namespaces],
        ['dataElements', options.dataElements],
      ])
    )
  }

  public get namespaces(): Array<Namespace> | undefined {
    return this.structure.get('nameSpaces') as Array<Namespace> | undefined
  }

  public get dataElements(): Map<Namespace, Array<DataElementIdentifier>> | undefined {
    return this.structure.get('dataElements') as Map<Namespace, Array<DataElementIdentifier>> | undefined
  }

  public override encodedStructure(): KeyAuthorizationsStructure {
    return super.encodedStructure() as KeyAuthorizationsStructure
  }
}
