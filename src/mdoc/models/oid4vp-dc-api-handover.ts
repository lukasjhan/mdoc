import { z } from 'zod'
import { buildStructure, type CborMap, cborArray } from '../../cbor'
import type { MdocContext } from '../../context'
import { Handover } from './handover'
import type { Oid4vpDcApiDraft24HandoverInfo } from './oid4vp-dc-api-draft24-handover-info'
import type { Oid4vpDcApiHandoverInfo } from './oid4vp-dc-api-handover-info'

const schema = cborArray([
  ['context', z.literal('OpenID4VPDCAPIHandover')],
  ['hash', z.instanceof(Uint8Array)],
])

export type Oid4vpDcApiHandoverStructure = [string, Uint8Array]

export type Oid4vpDcApiHandoverOptions = {
  oid4vpDcApiHandoverInfo?: Oid4vpDcApiHandoverInfo | Oid4vpDcApiDraft24HandoverInfo
  oid4vpDcApiHandoverInfoHash?: Uint8Array
}

export class Oid4vpDcApiHandover extends Handover {
  public static override schema = schema

  // The handover info is the input the hash is taken over, not wire data.
  protected info?: Oid4vpDcApiHandoverInfo | Oid4vpDcApiDraft24HandoverInfo

  public constructor(options: Oid4vpDcApiHandoverOptions) {
    super(
      buildStructure([
        ['context', 'OpenID4VPDCAPIHandover'],
        ['hash', options.oid4vpDcApiHandoverInfoHash],
      ])
    )

    this.info = options.oid4vpDcApiHandoverInfo
  }

  public get oid4vpDcApiHandoverInfo(): Oid4vpDcApiHandoverInfo | Oid4vpDcApiDraft24HandoverInfo | undefined {
    return this.info
  }

  public get oid4vpDcApiHandoverInfoHash(): Uint8Array | undefined {
    return this.structure.get('hash') as Uint8Array | undefined
  }

  /**
   * Returns a copy carrying the digest over the handover info. The receiver is
   * unchanged, so a handover never gains its hash after being handed out.
   */
  public async prepare(ctx: Pick<MdocContext, 'crypto'>): Promise<this> {
    if (!this.info && !this.oid4vpDcApiHandoverInfoHash) {
      throw new Error(`Either the 'oid4vpDcApiHandoverInfo' or 'oid4vpDcApiHandoverInfoHash' must be set`)
    }

    if (!this.info) return this

    const hash = await ctx.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: this.info.encode() })

    const copy = Object.create(Object.getPrototypeOf(this)) as this & {
      structure: CborMap
      info?: Oid4vpDcApiHandoverInfo | Oid4vpDcApiDraft24HandoverInfo
    }

    copy.structure = new Map(this.structure).set('hash', hash)
    copy.info = this.info

    return copy
  }

  public override encodedStructure(): Oid4vpDcApiHandoverStructure {
    if (!this.oid4vpDcApiHandoverInfoHash) {
      throw new Error('Call `prepare` first to create the hash over the handover info')
    }

    return super.encodedStructure() as Oid4vpDcApiHandoverStructure
  }

  public static override isCorrectHandover(structure: unknown): structure is Oid4vpDcApiHandoverStructure {
    return Array.isArray(structure) && structure[0] === 'OpenID4VPDCAPIHandover' && structure[1] instanceof Uint8Array
  }
}
