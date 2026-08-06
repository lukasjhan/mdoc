import { z } from 'zod'
import { type CborDecodeOptions, CborStructure, cborDynamicMap, decodeBytes, fromEncoded } from '../../cbor'
import type { DocType } from './doctype'
import type { ErrorCode } from './error-code'

const schema = cborDynamicMap(z.string(), z.number())

export type DocumentErrorStructure = Map<DocType, ErrorCode>

export type DocumentErrorOptions = {
  documentError: Map<DocType, ErrorCode>
}

export class DocumentError extends CborStructure {
  public static override schema = schema

  public constructor(options: DocumentErrorOptions) {
    super(new Map(options.documentError))
  }

  public get documentError(): Map<DocType, ErrorCode> {
    return this.structure as Map<DocType, ErrorCode>
  }

  public override encodedStructure(): DocumentErrorStructure {
    return super.encodedStructure() as DocumentErrorStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): DocumentError {
    return fromEncoded(DocumentError, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DocumentError {
    return decodeBytes(DocumentError, bytes, options)
  }
}
