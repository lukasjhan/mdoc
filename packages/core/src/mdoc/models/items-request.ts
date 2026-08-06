import { z } from 'zod'
import { buildStructure, CborStructure, cborMap } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DocType } from './doctype'
import type { IntentToRetain } from './itent-to-retain'
import type { Namespace } from './namespace'

const schema = cborMap([
  ['docType', z.string()],
  ['nameSpaces', z.map(z.string(), z.map(z.string(), z.boolean()))],
])

export type ItemsRequestStructure = {
  docType: DocType
  nameSpaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
}

export type ItemsRequestOptions = {
  docType: DocType
  namespaces:
    | Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
    | Record<Namespace, Record<DataElementIdentifier, IntentToRetain>>
}

export class ItemsRequest extends CborStructure {
  public static override schema = schema

  public constructor(options: ItemsRequestOptions) {
    super(
      buildStructure([
        ['docType', options.docType],
        [
          'nameSpaces',
          options.namespaces instanceof Map
            ? options.namespaces
            : new Map(Object.entries(options.namespaces).map(([ns, inner]) => [ns, new Map(Object.entries(inner))])),
        ],
      ])
    )
  }

  public get docType(): DocType {
    return this.structure.get('docType') as DocType
  }

  public get namespaces(): Map<Namespace, Map<DataElementIdentifier, IntentToRetain>> {
    return this.structure.get('nameSpaces') as Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
  }

  public override encodedStructure(): ItemsRequestStructure {
    return super.encodedStructure() as ItemsRequestStructure
  }
}
