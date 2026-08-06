import { z } from 'zod'
import { buildStructure, CborStructure, cborArray, DataItem } from '../../cbor'
import type { MdocContext } from '../../context'
import { DeviceEngagement, type DeviceEngagementStructure } from './device-engagement'
import { EReaderKey, type EReaderKeyStructure } from './e-reader-key'
import { Handover } from './handover'
import { IsoMdocDcApiHandover, type IsoMdocDcApiHandoverOptions } from './iso-mdoc-dc-api-handover'
import { NfcHandover } from './nfc-handover'
import {
  Oid4vpDcApiDraft24HandoverInfo,
  type Oid4vpDcApiDraft24HandoverInfoOptions,
} from './oid4vp-dc-api-draft24-handover-info'
import { Oid4vpDcApiHandover } from './oid4vp-dc-api-handover'
import { Oid4vpDcApiHandoverInfo, type Oid4vpDcApiHandoverInfoOptions } from './oid4vp-dc-api-handover-info'
import { Oid4vpDraft18Handover } from './oid4vp-draft18-handover'
import { Oid4vpHandover } from './oid4vp-handover'
import { Oid4vpHandoverInfo, type Oid4vpHandoverInfoOptions } from './oid4vp-handover-info'
import { QrHandover } from './qr-handover'

type DecodableStructure<T extends CborStructure> = { fromEncodedStructure(encodedStructure: unknown): T }

/**
 * Positions 0 and 1 are a tag-24 data item or null, and the bytes matter: the
 * session keys are derived over them, so a decoded structure has to re-encode
 * to what it arrived as. Going through the model's own `encode` is what keeps
 * `EReaderKey`'s preserved bytes intact.
 */
const optionalDataItem = <T extends CborStructure>(Class: DecodableStructure<T>) =>
  z.codec(
    z.custom<DataItem | null>((value) => value instanceof DataItem || value === null),
    z.custom<T | null>((value) => value instanceof CborStructure || value === null),
    {
      decode: (dataItem) => (dataItem === null ? null : Class.fromEncodedStructure(dataItem.data)),
      encode: (instance) => (instance === null ? null : new DataItem({ buffer: instance.encode() })),
    }
  )

/**
 * The handover is one of six shapes with no discriminator of its own, so each
 * candidate is asked whether the structure is its own.
 */
const handoverCodec = z.codec(
  z.unknown(),
  z.custom<Handover>((value) => value instanceof Handover),
  {
    decode: (encoded) => {
      // Typed without the individual predicates so that narrowing from one
      // candidate does not carry into the next.
      const candidates: Array<{
        isCorrectHandover(structure: unknown): boolean
        fromEncodedStructure(structure: unknown): Handover
      }> = [NfcHandover, QrHandover, Oid4vpHandover, Oid4vpDraft18Handover, Oid4vpDcApiHandover, IsoMdocDcApiHandover]

      for (const candidate of candidates) {
        if (candidate.isCorrectHandover(encoded)) return candidate.fromEncodedStructure(encoded)
      }

      throw new Error('Could not establish specific handover structure')
    },
    encode: (handover) => handover.encodedStructure(),
  }
)

const schema = cborArray([
  ['deviceEngagement', optionalDataItem(DeviceEngagement)],
  ['eReaderKey', optionalDataItem(EReaderKey)],
  ['handover', handoverCodec],
])

export type SessionTranscriptStructure = [
  DataItem<DeviceEngagementStructure> | null,
  DataItem<EReaderKeyStructure> | null,
  unknown,
]

export type SessionTranscriptOptions = {
  deviceEngagement?: DeviceEngagement
  eReaderKey?: EReaderKey
  handover: Handover
}

export class SessionTranscript extends CborStructure {
  public static override schema = schema

  public constructor(options: SessionTranscriptOptions) {
    super(
      buildStructure([
        ['deviceEngagement', options.deviceEngagement ?? null],
        ['eReaderKey', options.eReaderKey ?? null],
        ['handover', options.handover],
      ])
    )
  }

  public get deviceEngagement(): DeviceEngagement | undefined {
    return (this.structure.get('deviceEngagement') as DeviceEngagement | null) ?? undefined
  }

  public get eReaderKey(): EReaderKey | undefined {
    return (this.structure.get('eReaderKey') as EReaderKey | null) ?? undefined
  }

  public get handover(): Handover {
    return this.structure.get('handover') as Handover
  }

  public override encodedStructure(): SessionTranscriptStructure {
    const isProximityHandover = this.handover instanceof QrHandover || this.handover instanceof NfcHandover

    if (isProximityHandover) {
      if (!this.deviceEngagement) {
        throw new Error('QR/NFC handover requires deviceEngagement')
      }
      if (!this.eReaderKey) {
        throw new Error('QR/NFC handover requires eReaderKey')
      }
    }

    return super.encodedStructure() as SessionTranscriptStructure
  }

  /**
   * Create a SessionTranscript for QR handover (ISO 18013-5 proximity presentation).
   *
   * For QR handover, exact CBOR bytes matter for session key derivation.
   * Use DeviceEngagement.decode() and EReaderKey.decode() to preserve original bytes -
   * calling encode() on decoded objects will return the identical bytes.
   */
  public static forQrHandover(options: { deviceEngagement: DeviceEngagement; eReaderKey: EReaderKey }) {
    return new SessionTranscript({
      deviceEngagement: options.deviceEngagement,
      eReaderKey: options.eReaderKey,
      handover: new QrHandover(),
    })
  }

  public static async forOid4VpDcApiDraft24(
    options: Oid4vpDcApiDraft24HandoverInfoOptions,
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const info = new Oid4vpDcApiDraft24HandoverInfo(options)
    const handover = await new Oid4vpDcApiHandover({ oid4vpDcApiHandoverInfo: info }).prepare(ctx)

    return new SessionTranscript({ handover })
  }

  public static async forOid4VpDcApi(options: Oid4vpDcApiHandoverInfoOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const info = new Oid4vpDcApiHandoverInfo(options)
    const handover = await new Oid4vpDcApiHandover({ oid4vpDcApiHandoverInfo: info }).prepare(ctx)

    return new SessionTranscript({ handover })
  }

  /**
   * Calculate the session transcript for the ISO 18013-7 Annex C `org-iso-mdoc`
   * DC API protocol, which a wallet answering an `org-iso-mdoc` request uses.
   */
  public static async forIsoMdocDcApi(
    options: Required<Pick<IsoMdocDcApiHandoverOptions, 'encryptionInfoBase64Url' | 'origin'>>,
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    return new SessionTranscript({ handover: await new IsoMdocDcApiHandover(options).prepare(ctx) })
  }

  public static async forOid4Vp(options: Oid4vpHandoverInfoOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const info = new Oid4vpHandoverInfo(options)
    const handover = await new Oid4vpHandover({ oid4vpHandoverInfo: info }).prepare(ctx)

    return new SessionTranscript({ handover })
  }

  /**
   * Calculate the session transcript bytes as defined in 18013-7 first edition, based
   * on OpenID4VP draft 18.
   */
  public static async forOid4VpDraft18(
    options: { clientId: string; responseUri: string; verifierGeneratedNonce: string; mdocGeneratedNonce: string },
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const handover = new Oid4vpDraft18Handover({
      clientId: options.clientId,
      nonce: options.verifierGeneratedNonce,
      mdocGeneratedNonce: options.mdocGeneratedNonce,
      responseUri: options.responseUri,
    })

    return new SessionTranscript({ handover: await handover.prepare(ctx) })
  }
}
