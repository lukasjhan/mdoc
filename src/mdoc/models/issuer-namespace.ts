import { z } from 'zod'
import { CborStructure, cborDataItem, cborDynamicMap, type DataItem } from '../../cbor'
import { IssuerSignedItem, type IssuerSignedItemStructure } from './issuer-signed-item'
import type { Namespace } from './namespace'

const schema = cborDynamicMap(z.string(), z.array(cborDataItem(IssuerSignedItem)))

export type IssuerNamespaceStructure = Map<Namespace, Array<DataItem<IssuerSignedItemStructure>>>

export type IssuerNamespaceOptions = {
  issuerNamespaces: Map<Namespace, Array<IssuerSignedItem>>
}

export class IssuerNamespace extends CborStructure {
  public static override schema = schema

  public constructor(options: IssuerNamespaceOptions) {
    super(new Map(options.issuerNamespaces))
  }

  public get issuerNamespaces(): Map<Namespace, Array<IssuerSignedItem>> {
    return this.structure as Map<Namespace, Array<IssuerSignedItem>>
  }

  public get(namespace: string) {
    return this.issuerNamespaces.get(namespace)
  }

  public override encodedStructure(): IssuerNamespaceStructure {
    return super.encodedStructure() as IssuerNamespaceStructure
  }
}
