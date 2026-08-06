import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  type CborMap,
  cborArray,
  cborEncode,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import type { MdocContext } from '../../context'
import { Handover } from './handover'

const schema = cborArray([
  ['clientIdHash', z.instanceof(Uint8Array)],
  ['responseUriHash', z.instanceof(Uint8Array)],
  ['nonce', z.string()],
])

export type Oid4vpDraft18HandoverStructure = [Uint8Array, Uint8Array, string]

export type Oid4vpDraft18HandoverOptions = {
  mdocGeneratedNonce?: string
  clientId?: string
  responseUri?: string
  nonce: string

  clientIdHash?: Uint8Array
  responseUriHash?: Uint8Array
}

/** The inputs the two hashes are taken over. Not wire data. */
type Draft18Inputs = {
  mdocGeneratedNonce?: string
  clientId?: string
  responseUri?: string
}

/**
 *
 * @note this will be removed as it is already a legacy handover structure
 *
 */
export class Oid4vpDraft18Handover extends Handover {
  public static override schema = schema

  protected inputs?: Draft18Inputs

  public constructor(options: Oid4vpDraft18HandoverOptions) {
    super(
      buildStructure([
        ['clientIdHash', options.clientIdHash],
        ['responseUriHash', options.responseUriHash],
        ['nonce', options.nonce],
      ])
    )

    this.inputs = {
      mdocGeneratedNonce: options.mdocGeneratedNonce,
      clientId: options.clientId,
      responseUri: options.responseUri,
    }
  }

  public get nonce(): string {
    return this.structure.get('nonce') as string
  }

  public get clientIdHash(): Uint8Array | undefined {
    return this.structure.get('clientIdHash') as Uint8Array | undefined
  }

  public get responseUriHash(): Uint8Array | undefined {
    return this.structure.get('responseUriHash') as Uint8Array | undefined
  }

  public get mdocGeneratedNonce(): string | undefined {
    return this.inputs?.mdocGeneratedNonce
  }

  public get clientId(): string | undefined {
    return this.inputs?.clientId
  }

  public get responseUri(): string | undefined {
    return this.inputs?.responseUri
  }

  /**
   * Returns a copy carrying the two digests. The receiver is unchanged, so a
   * handover never gains its hashes after being handed out.
   */
  public async prepare(ctx: Pick<MdocContext, 'crypto'>): Promise<this> {
    const { clientId, responseUri, mdocGeneratedNonce } = this.inputs ?? {}

    if ((!mdocGeneratedNonce || !clientId || !responseUri) && (!this.clientIdHash || !this.responseUriHash)) {
      throw new Error(
        'Either the responseUriHash and clientIdHash must be set or the clientId, responseUri and mdocGeneratedNonce'
      )
    }

    const structure = new Map(this.structure)

    if (clientId && mdocGeneratedNonce) {
      structure.set(
        'clientIdHash',
        await ctx.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: cborEncode([clientId, mdocGeneratedNonce]) })
      )
    }

    if (responseUri && mdocGeneratedNonce) {
      structure.set(
        'responseUriHash',
        await ctx.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: cborEncode([responseUri, mdocGeneratedNonce]) })
      )
    }

    if (!structure.get('clientIdHash') || !structure.get('responseUriHash')) {
      throw new Error(
        'Could not hash the client id and/or the response uri. Make sure the properties are set on the class, or manually provide the hashed client id and response uri with the mdoc generated nonce'
      )
    }

    const copy = Object.create(Object.getPrototypeOf(this)) as this & { structure: CborMap; inputs?: Draft18Inputs }

    copy.structure = structure
    copy.inputs = this.inputs

    return copy
  }

  public override encodedStructure(): Oid4vpDraft18HandoverStructure {
    if (!this.clientIdHash || !this.responseUriHash) {
      throw new Error('Call `prepare` first to create the hash over the client id and response uri')
    }

    return super.encodedStructure() as Oid4vpDraft18HandoverStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): Oid4vpDraft18Handover {
    return fromEncoded(Oid4vpDraft18Handover, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Oid4vpDraft18Handover {
    return decodeBytes(Oid4vpDraft18Handover, bytes, options)
  }

  public static override isCorrectHandover(structure: unknown): structure is Oid4vpDraft18HandoverStructure {
    return (
      Array.isArray(structure) &&
      structure[0] instanceof Uint8Array &&
      structure[1] instanceof Uint8Array &&
      typeof structure[2] === 'string'
    )
  }
}
