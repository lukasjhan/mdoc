import type { MdocContext, X509Context } from '../../c-mdoc.js';
import { DataItem } from '../../cbor/data-item.js';
import { cborDecode } from '../../cbor/index.js';
import type { ProtectedHeaders, UnprotectedHeaders } from '../../cose/headers.js';
import { Sign1 } from '../../cose/sign1.js';
import type { MSO } from './types.js';

/**
 * The IssuerAuth which is a COSE_Sign1 message
 * as defined in https://www.iana.org/assignments/cose/cose.xhtml#messages
 */
export default class IssuerAuth extends Sign1 {
  #decodedPayload?: MSO;
  #certificate?: Uint8Array;

  constructor(
    protectedHeader: Map<number, unknown> | Uint8Array,
    unprotectedHeader: Map<number, unknown>,
    payload: Uint8Array,
    signature: Uint8Array
  ) {
    super(protectedHeader, unprotectedHeader, payload, signature);
  }

  public get decodedPayload(): MSO {
    if (this.#decodedPayload) {
      return this.#decodedPayload;
    }

    let decoded = cborDecode(this.payload);
    decoded = decoded instanceof DataItem ? decoded.data : decoded;
    decoded = Object.fromEntries(decoded);
    const mapValidityInfo = (validityInfo: Map<string, Uint8Array>) => {
      if (!validityInfo) {
        return validityInfo;
      }
      return Object.fromEntries(
        [...validityInfo.entries()].map(([key, value]) => {
          return [key, value instanceof Uint8Array ? cborDecode(value) : value];
        })
      );
    };
    const result: MSO = {
      ...decoded,
      validityInfo: mapValidityInfo(decoded.validityInfo),
      validityDigests: decoded.validityDigests
        ? Object.fromEntries(decoded.validityDigests)
        : decoded.validityDigests,
      deviceKeyInfo: decoded.deviceKeyInfo
        ? Object.fromEntries(decoded.deviceKeyInfo)
        : decoded.deviceKeyInfo,
    };
    this.#decodedPayload = result;
    return result;
  }

  public get certificate() {
    if (typeof this.#certificate === 'undefined' && this.x5chain?.[0]) {
      this.#certificate = this.x5chain[0];
    }

    if (!this.#certificate) {
      throw new Error('No certificate found');
    }
    return this.#certificate;
  }

  public getIssuingCountry(ctx: { x509: X509Context }) {
    const countryName = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'C',
    })[0];

    return countryName;
  }

  public getIssuingStateOrProvince(ctx: { x509: X509Context }) {
    const stateOrProvince = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'ST',
    })[0];

    return stateOrProvince;
  }

  static override async sign(
    protectedHeaders: ProtectedHeaders,
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: Uint8Array,
    ctx: { cose: MdocContext['cose']; crypto: MdocContext['crypto'] }
  ): Promise<IssuerAuth> {
    const sign1 = await Sign1.sign(
      protectedHeaders,
      unprotectedHeaders,
      payload,
      key,
      ctx
    );

    return new IssuerAuth(
      sign1.protectedHeaders,
      sign1.unprotectedHeaders,
      sign1.payload,
      sign1.signature
    );
  }
}
