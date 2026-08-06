import { z } from 'zod'
import { buildStructure, type CborMap, cborArray } from '../../cbor'
import type { MdocContext } from '../../context'
import { Handover } from './handover'
import type { Oid4vpHandoverInfo } from './oid4vp-handover-info'

const schema = cborArray([
  ['context', z.literal('OpenID4VPHandover')],
  ['hash', z.instanceof(Uint8Array)],
])

export type Oid4vpHandoverStructure = [string, Uint8Array]

export type Oid4vpHandoverOptions = {
  oid4vpHandoverInfo?: Oid4vpHandoverInfo
  oid4vpHandoverInfoHash?: Uint8Array
}

export class Oid4vpHandover extends Handover {
  public static override schema = schema

  // The handover info is the input the hash is taken over, not wire data.
  protected info?: Oid4vpHandoverInfo

  public constructor(options: Oid4vpHandoverOptions) {
    super(
      buildStructure([
        ['context', 'OpenID4VPHandover'],
        ['hash', options.oid4vpHandoverInfoHash],
      ])
    )

    this.info = options.oid4vpHandoverInfo
  }

  public get oid4vpHandoverInfo(): Oid4vpHandoverInfo | undefined {
    return this.info
  }

  public get oid4vpHandoverInfoHash(): Uint8Array | undefined {
    return this.structure.get('hash') as Uint8Array | undefined
  }

  /**
   * Returns a copy carrying the digest over the handover info. The receiver is
   * unchanged, so a handover never gains its hash after being handed out.
   */
  public async prepare(ctx: Pick<MdocContext, 'crypto'>): Promise<this> {
    if (!this.info && !this.oid4vpHandoverInfoHash) {
      throw new Error(`Either the 'oid4vpHandoverInfo' or 'oid4vpHandoverInfoHash' must be set`)
    }

    if (!this.info) return this

    const hash = await ctx.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: this.info.encode() })

    const copy = Object.create(Object.getPrototypeOf(this)) as this & {
      structure: CborMap
      info?: Oid4vpHandoverInfo
    }

    copy.structure = new Map(this.structure).set('hash', hash)
    copy.info = this.info

    return copy
  }

  public override encodedStructure(): Oid4vpHandoverStructure {
    if (!this.oid4vpHandoverInfoHash) {
      throw new Error('Call `prepare` first to create the hash over the handover info')
    }

    return super.encodedStructure() as Oid4vpHandoverStructure
  }

  public static override isCorrectHandover(structure: unknown): structure is Oid4vpHandoverStructure {
    return Array.isArray(structure) && structure[0] === 'OpenID4VPHandover' && structure[1] instanceof Uint8Array
  }
}
