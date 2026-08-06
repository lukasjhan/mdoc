import { z } from 'zod'
import { type CborDecodeOptions, CborStructure, cborDynamicMap, decodeBytes, fromEncoded } from '../../cbor'
import type { Digest } from './digest'
import type { DigestId } from './digest-id'
import type { Namespace } from './namespace'

const schema = cborDynamicMap(z.string(), z.map(z.number(), z.instanceof(Uint8Array)))

export type ValueDigestOptions = {
  valueDigests: Map<Namespace, Map<DigestId, Digest>>
}

export class ValueDigests extends CborStructure {
  public static override schema = schema

  public constructor(options: ValueDigestOptions) {
    super(options.valueDigests)
  }

  public get valueDigests(): Map<Namespace, Map<DigestId, Digest>> {
    return this.structure as Map<Namespace, Map<DigestId, Digest>>
  }

  public static override fromEncodedStructure(encodedStructure: unknown): ValueDigests {
    return fromEncoded(ValueDigests, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ValueDigests {
    return decodeBytes(ValueDigests, bytes, options)
  }
}
