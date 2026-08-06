import { z } from 'zod'
import { buildStructure, type CborDecodeOptions, CborStructure, cborMap, decodeBytes, fromEncoded } from '../../cbor'

const schema = cborMap([
  ['signed', z.date()],
  ['validFrom', z.date()],
  ['validUntil', z.date()],
  ['expectedUpdate', z.date().optional()],
])

export type ValidityInfoOptions = {
  signed: Date
  validFrom: Date
  validUntil: Date
  expectedUpdate?: Date
}

export class ValidityInfo extends CborStructure {
  public static override schema = schema

  public constructor(options: ValidityInfoOptions) {
    super(
      buildStructure([
        ['signed', options.signed],
        ['validFrom', options.validFrom],
        ['validUntil', options.validUntil],
        ['expectedUpdate', options.expectedUpdate],
      ])
    )
  }

  public get signed(): Date {
    return this.structure.get('signed') as Date
  }

  public get validFrom(): Date {
    return this.structure.get('validFrom') as Date
  }

  public get validUntil(): Date {
    return this.structure.get('validUntil') as Date
  }

  public get expectedUpdate(): Date | undefined {
    return this.structure.get('expectedUpdate') as Date | undefined
  }

  public isSignedBetweenDates(notBefore: Date, notAfter: Date, skewSeconds = 30): boolean {
    const skewMs = skewSeconds * 1000
    const notBeforeWithSkew = new Date(notBefore.getTime() - skewMs)
    const notAfterWithSkew = new Date(notAfter.getTime() + skewMs)
    const isWithinRange = this.signed > notBeforeWithSkew && this.signed < notAfterWithSkew
    return isWithinRange
  }

  public isValidUntilAfterNow(now: Date = new Date(), skewSeconds = 30): boolean {
    const skewMs = skewSeconds * 1000
    const validUntilWithSkew = new Date(this.validUntil.getTime() + skewMs)
    return validUntilWithSkew >= now
  }

  public isValidFromBeforeNow(now: Date = new Date(), skewSeconds = 30): boolean {
    const skewMs = skewSeconds * 1000
    const validFromWithSkew = new Date(this.validFrom.getTime() - skewMs)
    return validFromWithSkew <= now
  }

  public static override fromEncodedStructure(encodedStructure: unknown): ValidityInfo {
    return fromEncoded(ValidityInfo, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ValidityInfo {
    return decodeBytes(ValidityInfo, bytes, options)
  }
}
