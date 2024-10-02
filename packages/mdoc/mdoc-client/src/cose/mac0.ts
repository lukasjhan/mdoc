import { addExtension, cborEncode } from '../cbor/index.js';
import { COSEBase } from './cose-base.js';
import { CoseError } from './e-cose.js';
import { ProtectedHeaders } from './headers';
import type { MacAlgorithms, SupportedMacAlg } from './headers.js';
import {
  Headers,
  MacAlgorithmNames,
  MacProtectedHeaders,
  UnprotectedHeaders,
} from './headers.js';
import { validateAlgorithms } from './validate-algorithms.js';
export interface VerifyOptions {
  externalAAD?: Uint8Array;
  detachedPayload?: Uint8Array;
  algorithms?: MacAlgorithms[];
}

export class Mac0 extends COSEBase {
  constructor(
    protectedHeaders: Map<number, unknown> | Uint8Array,
    unprotectedHeaders: Map<number, unknown>,
    public readonly payload: Uint8Array,
    private _tag?: Uint8Array
  ) {
    super(protectedHeaders, unprotectedHeaders);
  }

  private static createMAC0(
    protectedHeaders: Uint8Array,
    applicationHeaders: Uint8Array,
    payload: Uint8Array
  ) {
    return cborEncode(['MAC0', protectedHeaders, applicationHeaders, payload]);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.tag,
    ];
  }

  public get tag() {
    if (!this._tag) {
      throw new Error('No signature present');
    }

    return this._tag;
  }

  public set tag(sig: Uint8Array) {
    this._tag = sig;
  }

  public get alg(): MacAlgorithms | undefined {
    return this.protectedHeaders.get(Headers.Algorithm) as MacAlgorithms;
  }

  public get algName(): SupportedMacAlg | undefined {
    return this.alg ? MacAlgorithmNames.get(this.alg) : undefined;
  }

  public hasSupportedAlg() {
    return !!this.algName;
  }

  static create(
    protectedHeaders:
      | MacProtectedHeaders
      | ConstructorParameters<typeof MacProtectedHeaders>[0],
    unprotectedHeaders:
      | UnprotectedHeaders
      | ConstructorParameters<typeof UnprotectedHeaders>[0]
      | undefined,
    payload: Uint8Array,
    signature?: Uint8Array
  ) {
    const wProtectedHeaders = MacProtectedHeaders.wrap(protectedHeaders);
    const mac0AlgName = wProtectedHeaders.get(Headers.Algorithm);
    const alg = mac0AlgName ? MacAlgorithmNames.get(mac0AlgName) : undefined;

    if (!alg) {
      throw new CoseError({
        code: 'COSE_INVALID_ALG',
        message: `The [${Headers.Algorithm}] (Algorithm) header must be set.`,
      });
    }

    const encodedProtectedHeaders = cborEncode(wProtectedHeaders.esMap);
    const wUnprotectedHeaders = UnprotectedHeaders.wrap(unprotectedHeaders);

    return new Mac0(
      encodedProtectedHeaders,
      wUnprotectedHeaders.esMap as Map<number, unknown>,
      payload,
      signature
    );
  }

  public getRawSigningData() {
    const algName = this.algName;
    if (!algName) {
      throw new CoseError({
        code: 'COSE_INVALID_ALG',
        message: `Cannot get raw signing data. Mac alg is not defined`,
      });
    }

    const toBeSigned = Mac0.createMAC0(
      cborEncode(ProtectedHeaders.wrap(this.protectedHeaders).esMap),
      new Uint8Array(),
      this.payload
    );

    return { data: toBeSigned, alg: algName };
  }

  public getRawVerificationData(options?: VerifyOptions) {
    const mac0Structure = Mac0.createMAC0(
      this.encodedProtectedHeaders ?? new Uint8Array(),
      options?.externalAAD ?? new Uint8Array(),
      options?.detachedPayload ?? this.payload
    );

    if (!this.alg || !this.algName || !MacAlgorithmNames.has(this.alg)) {
      throw new CoseError({
        code: 'COSE_UNSUPPORTED_MAC',
        message: `Unsupported MAC algorithm '${this.alg}'`,
      });
    }

    const algorithms =
      options && validateAlgorithms('algorithms', options.algorithms);

    if (algorithms && !algorithms.has(this.alg)) {
      throw new CoseError({
        code: 'COSE_UNSUPPORTED_ALG',
        message: `[${Headers.Algorithm}] (algorithm) Header Parameter not allowed`,
      });
    }

    return {
      algName: this.algName,
      signature: this.tag,
      mac0Structure: mac0Structure,
    };
  }

  static tag = 17;
}

addExtension({
  Class: Mac0,
  tag: Mac0.tag,
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Mac0>) => {
    return new Mac0(data[0], data[1], data[2], data[3]);
  },
});
