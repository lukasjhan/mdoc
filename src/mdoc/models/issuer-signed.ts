import { buildStructure, CborStructure, cborMap, cborStructure } from '../../cbor'
import type { MdocContext } from '../../context'
import { base64url } from '../../utils'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback'
import { IssuerAuth, type IssuerAuthStructure } from './issuer-auth'
import { IssuerNamespace, type IssuerNamespaceStructure } from './issuer-namespace'
import type { IssuerSignedItem } from './issuer-signed-item'
import type { Namespace } from './namespace'

const schema = cborMap([
  ['nameSpaces', cborStructure(IssuerNamespace).optional()],
  ['issuerAuth', cborStructure(IssuerAuth)],
])

export type IssuerSignedStructure = {
  nameSpaces?: IssuerNamespaceStructure
  issuerAuth: IssuerAuthStructure
}

export type IssuerSignedOptions = {
  issuerNamespaces?: IssuerNamespace
  issuerAuth: IssuerAuth
}

export class IssuerSigned extends CborStructure {
  public static override schema = schema

  public constructor(options: IssuerSignedOptions) {
    super(
      buildStructure([
        ['nameSpaces', options.issuerNamespaces],
        ['issuerAuth', options.issuerAuth],
      ])
    )
  }

  public get issuerNamespaces(): IssuerNamespace | undefined {
    return this.structure.get('nameSpaces') as IssuerNamespace | undefined
  }

  public get issuerAuth(): IssuerAuth {
    return this.structure.get('issuerAuth') as IssuerAuth
  }

  public getIssuerNamespace(namespace: Namespace) {
    return this.issuerNamespaces?.get(namespace)
  }

  public getPrettyClaims(namespace: Namespace) {
    if (!this.issuerNamespaces) return undefined
    const issuerSignedItems = this.issuerNamespaces.issuerNamespaces.get(namespace)
    if (!issuerSignedItems) return undefined

    return issuerSignedItems.reduce((prev, curr) => ({ ...prev, [curr.elementIdentifier]: curr.elementValue }), {})
  }

  public get encodedForOid4Vci() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vci(encoded: string): IssuerSigned {
    return IssuerSigned.decode(base64url.decode(encoded))
  }

  public async verify(
    options: { verificationCallback?: VerificationCallback },
    ctx: Pick<MdocContext, 'x509' | 'crypto'>
  ) {
    const { valueDigests, digestAlgorithm } = this.issuerAuth.mobileSecurityObject

    const onCheck = onCategoryCheck(options.verificationCallback ?? defaultVerificationCallback, 'DATA_INTEGRITY')

    onCheck({
      status: digestAlgorithm ? 'PASSED' : 'FAILED',
      check: 'Issuer Auth must include a supported digestAlgorithm element',
    })

    const namespaces = this.issuerNamespaces?.issuerNamespaces ?? new Map<string, IssuerSignedItem[]>()

    await Promise.all(
      Array.from(namespaces.entries()).map(async ([ns, nsItems]) => {
        onCheck({
          status: valueDigests?.valueDigests.has(ns) ? 'PASSED' : 'FAILED',
          check: `Issuer Auth must include digests for namespace: ${ns}`,
        })

        const verifications = await Promise.all(
          nsItems.map(async (ev) => {
            const isValid = await ev.isValid(ns, this.issuerAuth, ctx)
            return { ev, ns, isValid }
          })
        )

        for (const verification of verifications.filter((v) => v.isValid)) {
          onCheck({
            status: 'PASSED',
            check: `The calculated digest for ${ns}/${verification.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
          })
        }

        for (const verification of verifications.filter((v) => !v.isValid)) {
          onCheck({
            status: 'FAILED',
            check: `The calculated digest for ${ns}/${verification.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
          })
        }

        if (ns === 'org.iso.18013.5.1') {
          const certificateData = await ctx.x509.getCertificateData({
            certificate: this.issuerAuth.certificate,
          })
          if (!certificateData.issuerName) {
            onCheck({
              status: 'FAILED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason:
                "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
            })
          } else {
            const invalidCountry = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
              .find((v) => !v.isValid || !v.ev.matchCertificate(this.issuerAuth, ctx))

            onCheck({
              status: invalidCountry ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason: invalidCountry
                ? `The 'issuing_country' (${invalidCountry.ev.elementValue}) must match the 'countryName' (${this.issuerAuth.getIssuingCountry(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })

            const invalidJurisdiction = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
              .find((v) => !v.isValid || !v.ev.matchCertificate(this.issuerAuth, ctx))

            onCheck({
              status: invalidJurisdiction ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
              reason: invalidJurisdiction
                ? `The 'issuing_jurisdiction' (${invalidJurisdiction.ev.elementValue}) must match the 'stateOrProvinceName' (${this.issuerAuth.getIssuingStateOrProvince(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })
          }
        }
      })
    )
  }

  public override encodedStructure(): IssuerSignedStructure {
    return super.encodedStructure() as IssuerSignedStructure
  }
}
