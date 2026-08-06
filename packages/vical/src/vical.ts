import { buildStructure, CborStructure, cborMap, cborStructure } from '@m-doc/core'
import { z } from 'zod'
import { CertificateInfo } from './certificate-info'

/** The docType an mDL IACA certificate is listed under. */
export const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL'

/** OID of the IACA certificate profile, ISO/IEC 18013-5 Annex B. */
export const IACA_CERTIFICATE_PROFILE = '1.0.18013.5.1.2'

/** OID of the extended key usage a VICAL signer certificate must carry. */
export const VICAL_EKU_OID = '1.0.18013.5.1.8'

/**
 * The payload of a VICAL — a Verified Issuer Certificate Authority List, the
 * trust list an mDL verifier checks issuer certificates against. ISO/IEC
 * 18013-5:2021 Annex C.
 *
 *   Vical = {
 *     "version": tstr,              ; "1.0"
 *     "vicalProvider": tstr,
 *     "date": tdate,
 *     ? "vicalIssueID": uint,       ; monotonically increasing
 *     ? "nextUpdate": tdate,
 *     "certificateInfos": [* CertificateInfo],
 *     ? "extensions": { * tstr => any },
 *     * tstr => any                 ; RFU
 *   }
 */
const schema = cborMap([
  ['version', z.string()],
  ['vicalProvider', z.string()],
  ['date', z.date()],
  ['vicalIssueID', z.number().optional()],
  ['nextUpdate', z.date().optional()],
  ['certificateInfos', z.array(cborStructure(CertificateInfo))],
  ['extensions', z.map(z.string(), z.unknown()).optional()],
])

export type VicalOptions = {
  version?: string
  vicalProvider: string
  date: Date
  vicalIssueID?: number
  nextUpdate?: Date
  certificateInfos: Array<CertificateInfo>
  extensions?: Map<string, unknown>
}

export class Vical extends CborStructure {
  public static override schema = schema

  public constructor(options: VicalOptions) {
    super(
      buildStructure([
        ['version', options.version ?? '1.0'],
        ['vicalProvider', options.vicalProvider],
        ['date', options.date],
        ['vicalIssueID', options.vicalIssueID],
        ['nextUpdate', options.nextUpdate],
        ['certificateInfos', options.certificateInfos],
        ['extensions', options.extensions],
      ])
    )
  }

  public get version(): string {
    return this.structure.get('version') as string
  }

  public get vicalProvider(): string {
    return this.structure.get('vicalProvider') as string
  }

  public get date(): Date {
    return this.structure.get('date') as Date
  }

  public get vicalIssueID(): number | undefined {
    return this.structure.get('vicalIssueID') as number | undefined
  }

  public get nextUpdate(): Date | undefined {
    return this.structure.get('nextUpdate') as Date | undefined
  }

  public get certificateInfos(): Array<CertificateInfo> {
    return this.structure.get('certificateInfos') as Array<CertificateInfo>
  }

  public get extensions(): Map<string, unknown> | undefined {
    return this.structure.get('extensions') as Map<string, unknown> | undefined
  }

  /** The entries listed for a docType. Defaults to the mDL docType. */
  public forDocType(docType: string = MDL_DOCTYPE): Array<CertificateInfo> {
    return this.certificateInfos.filter((info) => info.docType.includes(docType))
  }

  /** The entry issued by a country, if the list has one. */
  public forCountry(countryCode: string): CertificateInfo | undefined {
    return this.certificateInfos.find((info) => info.issuingCountry === countryCode)
  }

  /** The entry whose Subject Key Identifier matches, if the list has one. */
  public forSubjectKeyIdentifier(ski: Uint8Array): CertificateInfo | undefined {
    return this.certificateInfos.find(
      (info) => info.ski.length === ski.length && info.ski.every((byte, index) => byte === ski[index])
    )
  }

  /**
   * The list arranged as trust anchors by issuing country.
   *
   * A country listing more than one certificate for the docType keeps the last
   * one, which is what the previous implementation did; read `forDocType` where
   * every entry matters.
   */
  public trustAnchors(docType: string = MDL_DOCTYPE): Map<string, CertificateInfo> {
    const anchors = new Map<string, CertificateInfo>()

    for (const info of this.forDocType(docType)) {
      if (info.issuingCountry) anchors.set(info.issuingCountry, info)
    }

    return anchors
  }

  /** Every listed certificate, ready to hand to an X.509 library. */
  public certificates(docType: string = MDL_DOCTYPE): Array<Uint8Array> {
    return this.forDocType(docType).map((info) => info.certificate)
  }
}
