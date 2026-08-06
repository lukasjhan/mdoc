import { z } from 'zod'
import { buildStructure, CborStructure, cborArray, cborDataItem, cborStructure, type DataItem } from '../../cbor'
import { ItemsRequest, type ItemsRequestStructure } from './items-request'
import { SessionTranscript, type SessionTranscriptStructure } from './session-transcript'

const schema = cborArray([
  ['context', z.literal('ReaderAuthentication')],
  ['sessionTranscript', cborStructure(SessionTranscript)],
  ['itemsRequest', cborDataItem(ItemsRequest)],
])

export type ReaderAuthenticationStructure = [string, SessionTranscriptStructure, DataItem<ItemsRequestStructure>]

export type ReaderAuthenticationOptions = {
  sessionTranscript: SessionTranscript
  itemsRequest: ItemsRequest
}

export class ReaderAuthentication extends CborStructure {
  public static override schema = schema

  public constructor(options: ReaderAuthenticationOptions) {
    super(
      buildStructure([
        ['context', 'ReaderAuthentication'],
        ['sessionTranscript', options.sessionTranscript],
        ['itemsRequest', options.itemsRequest],
      ])
    )
  }

  public get sessionTranscript(): SessionTranscript {
    return this.structure.get('sessionTranscript') as SessionTranscript
  }

  public get itemsRequest(): ItemsRequest {
    return this.structure.get('itemsRequest') as ItemsRequest
  }

  public override encodedStructure(): ReaderAuthenticationStructure {
    return super.encodedStructure() as ReaderAuthenticationStructure
  }
}
