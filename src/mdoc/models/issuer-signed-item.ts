import { z } from 'zod'
import { buildStructure, CborStructure, cborMap } from '../../cbor'
import type { MdocContext } from '../../context'
import { compareBytes } from '../../utils'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import type { IssuerAuth } from './issuer-auth'
import type { Namespace } from './namespace'

// The wire spells it digestID; the accessor below keeps this library's digestId.
const schema = cborMap([
  ['digestID', z.number()],
  ['random', z.instanceof(Uint8Array)],
  ['elementIdentifier', z.string()],
  ['elementValue', z.unknown()],
])

export interface IssuerSignedItemStructure {
  digestID: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export type IssuerSignedItemOptions = {
  digestId: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export class IssuerSignedItem extends CborStructure {
  public static override schema = schema

  private constructor(options: IssuerSignedItemOptions) {
    super(
      buildStructure([
        ['digestID', options.digestId],
        ['random', options.random],
        ['elementIdentifier', options.elementIdentifier],
        ['elementValue', options.elementValue],
      ])
    )
  }

  public get digestId(): number {
    return this.structure.get('digestID') as number
  }

  public get random(): Uint8Array {
    return this.structure.get('random') as Uint8Array
  }

  public get elementIdentifier(): DataElementIdentifier {
    return this.structure.get('elementIdentifier') as DataElementIdentifier
  }

  public get elementValue(): DataElementValue {
    return this.structure.get('elementValue')
  }

  public async isValid(namespace: Namespace, issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'crypto'>) {
    const digest = await ctx.crypto.digest({
      digestAlgorithm: issuerAuth.mobileSecurityObject.digestAlgorithm,
      bytes: this.encode({ asDataItem: true }),
    })

    const valueDigests = issuerAuth.mobileSecurityObject.valueDigests.valueDigests
    const digests = valueDigests.get(namespace)

    if (!digests) {
      return false
    }

    const expectedDigest = digests.get(this.digestId)

    return expectedDigest !== undefined && compareBytes(digest, expectedDigest)
  }

  public matchCertificate(issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'x509'>) {
    if (this.elementIdentifier === 'issuing_country') {
      return this.elementValue === issuerAuth.getIssuingCountry(ctx)
    }

    if (this.elementIdentifier === 'issuing_jurisdiction') {
      return this.elementValue === issuerAuth.getIssuingStateOrProvince(ctx)
    }

    return false
  }

  public static fromOptions(options: IssuerSignedItemOptions) {
    return new IssuerSignedItem(options)
  }

  public override encodedStructure(): IssuerSignedItemStructure {
    return super.encodedStructure() as IssuerSignedItemStructure
  }
}
