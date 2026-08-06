import { z } from 'zod'
import { buildStructure, type CborMap, cborArray, cborEncode } from '../../cbor'
import type { MdocContext } from '../../context'
import { Handover } from './handover'

const schema = cborArray([
  ['context', z.literal('dcapi')],
  ['hash', z.instanceof(Uint8Array)],
])

export type IsoMdocDcApiHandoverStructure = [string, Uint8Array]

export type IsoMdocDcApiHandoverOptions = {
  encryptionInfoBase64Url?: string
  origin?: string
  dcApiInfoHash?: Uint8Array
}

/** The inputs the hash is taken over. Not wire data. */
type IsoMdocDcApiInputs = {
  encryptionInfoBase64Url?: string
  origin?: string
}

/**
 * Handover for the ISO 18013-7 Annex C `org-iso-mdoc` DC API protocol.
 *
 *   DCAPIHandover = [ "dcapi", SHA-256(CBOR([encryptionInfoBase64Url, origin])) ]
 *
 * Distinct from the OpenID4VP DC API handover, and needed to verify a response
 * from a wallet that answered an `org-iso-mdoc` request.
 */
export class IsoMdocDcApiHandover extends Handover {
  public static override schema = schema

  protected inputs?: IsoMdocDcApiInputs

  public constructor(options: IsoMdocDcApiHandoverOptions) {
    super(
      buildStructure([
        ['context', 'dcapi'],
        ['hash', options.dcApiInfoHash],
      ])
    )

    this.inputs = { encryptionInfoBase64Url: options.encryptionInfoBase64Url, origin: options.origin }
  }

  public get encryptionInfoBase64Url(): string | undefined {
    return this.inputs?.encryptionInfoBase64Url
  }

  public get origin(): string | undefined {
    return this.inputs?.origin
  }

  public get dcApiInfoHash(): Uint8Array | undefined {
    return this.structure.get('hash') as Uint8Array | undefined
  }

  /**
   * Returns a copy carrying the digest over the encryption info and origin. The
   * receiver is unchanged, so a handover never gains its hash after being
   * handed out.
   */
  public async prepare(ctx: Pick<MdocContext, 'crypto'>): Promise<this> {
    const { encryptionInfoBase64Url, origin } = this.inputs ?? {}

    if ((!encryptionInfoBase64Url || !origin) && !this.dcApiInfoHash) {
      throw new Error(`Either the 'encryptionInfoBase64Url' and 'origin', or the 'dcApiInfoHash', must be set`)
    }

    if (!encryptionInfoBase64Url || !origin) return this

    const hash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: cborEncode([encryptionInfoBase64Url, origin]),
    })

    const copy = Object.create(Object.getPrototypeOf(this)) as this & {
      structure: CborMap
      inputs?: IsoMdocDcApiInputs
    }

    copy.structure = new Map(this.structure).set('hash', hash)
    copy.inputs = this.inputs

    return copy
  }

  public override encodedStructure(): IsoMdocDcApiHandoverStructure {
    if (!this.dcApiInfoHash) {
      throw new Error('Call `prepare` first to create the hash over the encryption info and origin')
    }

    return super.encodedStructure() as IsoMdocDcApiHandoverStructure
  }

  public static override isCorrectHandover(structure: unknown): structure is IsoMdocDcApiHandoverStructure {
    return Array.isArray(structure) && structure[0] === 'dcapi' && structure[1] instanceof Uint8Array
  }
}
