import { type CoseKey, cborDecode, type MdocContext, Sign1 } from '@m-doc/core'
import { Vical } from './vical'

export class VicalError extends Error {
  public constructor(
    message: string,
    public readonly cause?: unknown
  ) {
    super(message)
    this.name = 'VicalError'
  }
}

/**
 * A VICAL as it is distributed: the list wrapped in a COSE_Sign1 signed by the
 * VICAL provider. ISO/IEC 18013-5:2021 Annex C.
 *
 * The signature is what makes the list worth anything, so verify before
 * trusting what `vical` returns.
 */
export class SignedVical extends Sign1 {
  private parsed?: Vical

  /** The list this structure carries. Parsed on first read. */
  public get vical(): Vical {
    if (this.parsed) return this.parsed

    if (!this.payload) throw new VicalError('The COSE_Sign1 carries no payload')

    try {
      this.parsed = Vical.fromEncodedStructure(cborDecode(this.payload))
    } catch (error) {
      throw new VicalError('Failed to decode the VICAL payload', error)
    }

    return this.parsed
  }

  /**
   * Checks the provider's signature.
   *
   * With no `key`, the public key is taken from the leaf of the `x5chain`
   * header — which says only that the list is internally consistent. Pass the
   * provider's known key, or validate the chain against a trust anchor, to
   * learn that it is the list you meant to fetch.
   */
  public async verify(options: { key?: CoseKey }, ctx: Pick<MdocContext, 'cose' | 'x509'>): Promise<boolean> {
    return this.verifySignature(options, ctx)
  }
}
