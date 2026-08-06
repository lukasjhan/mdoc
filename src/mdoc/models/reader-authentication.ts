import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborArray,
  cborDataItem,
  cborStructure,
  type DataItem,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
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

  public static override fromEncodedStructure(encodedStructure: unknown): ReaderAuthentication {
    return fromEncoded(ReaderAuthentication, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ReaderAuthentication {
    return decodeBytes(ReaderAuthentication, bytes, options)
  }
}
