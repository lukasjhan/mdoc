import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborDataItem,
  cborMap,
  cborStructure,
  type DataItem,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import { ItemsRequest, type ItemsRequestStructure } from './items-request'
import { ReaderAuth, type ReaderAuthStructure } from './reader-auth'

const schema = cborMap([
  ['itemsRequest', cborDataItem(ItemsRequest)],
  ['readerAuth', cborStructure(ReaderAuth).optional()],
])

export type DocRequestStructure = {
  itemsRequest: DataItem<ItemsRequestStructure>
  readerAuth?: ReaderAuthStructure
}

export type DocRequestOptions = {
  itemsRequest: ItemsRequest
  readerAuth?: ReaderAuth
}

export class DocRequest extends CborStructure {
  public static override schema = schema

  public constructor(options: DocRequestOptions) {
    super(
      buildStructure([
        ['itemsRequest', options.itemsRequest],
        ['readerAuth', options.readerAuth],
      ])
    )
  }

  public get itemsRequest(): ItemsRequest {
    return this.structure.get('itemsRequest') as ItemsRequest
  }

  public get readerAuth(): ReaderAuth | undefined {
    return this.structure.get('readerAuth') as ReaderAuth | undefined
  }

  public override encodedStructure(): DocRequestStructure {
    return super.encodedStructure() as DocRequestStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): DocRequest {
    return fromEncoded(DocRequest, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DocRequest {
    return decodeBytes(DocRequest, bytes, options)
  }
}
