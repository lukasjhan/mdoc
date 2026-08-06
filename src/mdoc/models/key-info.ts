import { z } from 'zod'
import { type CborDecodeOptions, CborStructure, cborDynamicMap, decodeBytes, fromEncoded } from '../../cbor'

const schema = cborDynamicMap(z.number(), z.unknown())

export type KeyInfoStructure = Map<number, unknown>

export type KeyInfoOptions = {
  keyInfo: Map<number, unknown>
}

export class KeyInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: KeyInfoOptions) {
    super(new Map(options.keyInfo))
  }

  public get keyInfo(): Map<number, unknown> {
    return this.structure as Map<number, unknown>
  }

  public override encodedStructure(): KeyInfoStructure {
    return super.encodedStructure() as KeyInfoStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): KeyInfo {
    return fromEncoded(KeyInfo, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): KeyInfo {
    return decodeBytes(KeyInfo, bytes, options)
  }
}
