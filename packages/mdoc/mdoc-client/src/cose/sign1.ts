import { addExtension, cborEncode } from '../cbor/index.js';
import { CoseError } from './e-cose.js';
import {
  AlgorithmNames,
  Headers,
  ProtectedHeaders,
  UnprotectedHeaders,
} from './headers.js';
import type { VerifyOptions } from './signature-base.js';
import { SignatureBase } from './signature-base.js';

export class Sign1 extends SignatureBase {
  constructor(
    protectedHeaders: Map<number, unknown> | Uint8Array,
    unprotectedHeaders: Map<number, unknown>,
    public readonly payload: Uint8Array,
    _signature?: Uint8Array
  ) {
    super(protectedHeaders, unprotectedHeaders, _signature);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.signature,
    ];
  }

  private static Signature1(
    protectedHeaders: Uint8Array,
    applicationHeaders: Uint8Array,
    payload: Uint8Array
  ) {
    return cborEncode([
      'Signature1',
      protectedHeaders,
      applicationHeaders,
      payload,
    ]);
  }

  public static create(
    protectedHeaders:
      | ProtectedHeaders
      | ConstructorParameters<typeof ProtectedHeaders>[0],
    unprotectedHeaders:
      | UnprotectedHeaders
      | ConstructorParameters<typeof UnprotectedHeaders>[0]
      | undefined,
    payload: Uint8Array,
    signature?: Uint8Array
  ) {
    const wProtectedHeaders = ProtectedHeaders.wrap(protectedHeaders);
    const sig1AlgName = wProtectedHeaders.get(Headers.Algorithm);
    const alg = sig1AlgName ? AlgorithmNames.get(sig1AlgName) : undefined;

    if (!alg) {
      throw new CoseError({
        code: 'COSE_INVALID_ALG',
        message: `The [${Headers.Algorithm}] (Algorithm) header must be set.`,
      });
    }

    const encodedProtectedHeaders = cborEncode(wProtectedHeaders.esMap);
    const wUnprotectedHeaders = UnprotectedHeaders.wrap(unprotectedHeaders);

    return new Sign1(
      encodedProtectedHeaders,
      wUnprotectedHeaders.esMap as Map<number, unknown>,
      payload,
      signature
    );
  }

  public getRawSigningData() {
    const alg = this.alg;
    if (!alg) {
      throw new CoseError({
        code: 'COSE_INVALID_ALG',
        message: `Cannot get raw signing data. Alg is not defined`,
      });
    }

    const toBeSigned = Sign1.Signature1(
      cborEncode(ProtectedHeaders.wrap(this.protectedHeaders).esMap),
      new Uint8Array(),
      this.payload
    );

    return {
      payload: toBeSigned,
      alg,
    };
  }

  public getRawVerificationData(options?: VerifyOptions) {
    const toBeSigned = Sign1.Signature1(
      this.encodedProtectedHeaders ?? new Uint8Array(),
      options?.externalAAD ?? new Uint8Array(),
      options?.detachedPayload ?? this.payload
    );

    return this.internalGetRawVerificationData(toBeSigned);
  }

  static tag = 18;
}

addExtension({
  Class: Sign1,
  tag: Sign1.tag,
  encode(instance: Sign1, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Sign1>) => {
    return new Sign1(data[0], data[1], data[2], data[3]);
  },
});
