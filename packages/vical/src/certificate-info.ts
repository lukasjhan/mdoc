import { buildStructure, CborStructure, cborMap } from '@m-doc/core'
import { z } from 'zod'

/**
 * One entry of a VICAL's `certificateInfos`, per ISO/IEC 18013-5:2021 Annex C.
 *
 *   CertificateInfo = {
 *     "certificate": bstr,          ; DER-encoded IACA certificate
 *     "serialNumber": biguint,
 *     "ski": bstr,                  ; Subject Key Identifier
 *     "docType": [+ tstr],
 *     ? "certificateProfile": [+ tstr],
 *     ? "issuingAuthority": tstr,
 *     ? "issuingCountry": tstr,
 *     ? "stateOrProvinceName": tstr,
 *     ? "issuer": bstr,             ; DER-encoded Issuer field
 *     ? "subject": bstr,            ; DER-encoded Subject field
 *     ? "notBefore": tdate,
 *     ? "notAfter": tdate,
 *     ? "extensions": { * tstr => any },
 *     * tstr => any                 ; RFU
 *   }
 */
const schema = cborMap([
  ['certificate', z.instanceof(Uint8Array)],
  // A biguint arrives as a bigint, or as a plain number when it fits
  ['serialNumber', z.union([z.bigint(), z.number()])],
  ['ski', z.instanceof(Uint8Array)],
  ['docType', z.array(z.string())],
  ['certificateProfile', z.array(z.string()).optional()],
  ['issuingAuthority', z.string().optional()],
  ['issuingCountry', z.string().optional()],
  ['stateOrProvinceName', z.string().optional()],
  ['issuer', z.instanceof(Uint8Array).optional()],
  ['subject', z.instanceof(Uint8Array).optional()],
  ['notBefore', z.date().optional()],
  ['notAfter', z.date().optional()],
  ['extensions', z.map(z.string(), z.unknown()).optional()],
])

export type CertificateInfoOptions = {
  certificate: Uint8Array
  serialNumber: bigint | number
  ski: Uint8Array
  docType: Array<string>
  certificateProfile?: Array<string>
  issuingAuthority?: string
  issuingCountry?: string
  stateOrProvinceName?: string
  issuer?: Uint8Array
  subject?: Uint8Array
  notBefore?: Date
  notAfter?: Date
  extensions?: Map<string, unknown>
}

export class CertificateInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: CertificateInfoOptions) {
    super(
      buildStructure([
        ['certificate', options.certificate],
        ['serialNumber', options.serialNumber],
        ['ski', options.ski],
        ['docType', options.docType],
        ['certificateProfile', options.certificateProfile],
        ['issuingAuthority', options.issuingAuthority],
        ['issuingCountry', options.issuingCountry],
        ['stateOrProvinceName', options.stateOrProvinceName],
        ['issuer', options.issuer],
        ['subject', options.subject],
        ['notBefore', options.notBefore],
        ['notAfter', options.notAfter],
        ['extensions', options.extensions],
      ])
    )
  }

  public get certificate(): Uint8Array {
    return this.structure.get('certificate') as Uint8Array
  }

  /** Always a bigint, even where the wire held a plain integer. */
  public get serialNumber(): bigint {
    return BigInt(this.structure.get('serialNumber') as bigint | number)
  }

  public get ski(): Uint8Array {
    return this.structure.get('ski') as Uint8Array
  }

  public get docType(): Array<string> {
    return this.structure.get('docType') as Array<string>
  }

  public get certificateProfile(): Array<string> | undefined {
    return this.structure.get('certificateProfile') as Array<string> | undefined
  }

  public get issuingAuthority(): string | undefined {
    return this.structure.get('issuingAuthority') as string | undefined
  }

  public get issuingCountry(): string | undefined {
    return this.structure.get('issuingCountry') as string | undefined
  }

  public get stateOrProvinceName(): string | undefined {
    return this.structure.get('stateOrProvinceName') as string | undefined
  }

  public get issuer(): Uint8Array | undefined {
    return this.structure.get('issuer') as Uint8Array | undefined
  }

  public get subject(): Uint8Array | undefined {
    return this.structure.get('subject') as Uint8Array | undefined
  }

  public get notBefore(): Date | undefined {
    return this.structure.get('notBefore') as Date | undefined
  }

  public get notAfter(): Date | undefined {
    return this.structure.get('notAfter') as Date | undefined
  }

  public get extensions(): Map<string, unknown> | undefined {
    return this.structure.get('extensions') as Map<string, unknown> | undefined
  }

  /** The certificate as a PEM block, for handing to an X.509 library. */
  public toPem(): string {
    const base64 = btoa(String.fromCharCode(...this.certificate))
    const lines = base64.match(/.{1,64}/g)?.join('\n') ?? base64

    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`
  }
}
