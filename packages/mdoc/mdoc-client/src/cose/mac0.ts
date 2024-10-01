import type { MdocContext } from '../c-mdoc.js';
import { addExtension, cborEncode } from '../cbor/index.js';
import { COSEBase } from './cose-base.js';
import type {
  MacAlgorithms} from './headers.js';
import {
  Headers,
  MacAlgorithmNames,
  MacProtectedHeaders,
  
  UnprotectedHeaders
} from './headers.js';
import type {SupportedMacAlg} from './headers.js';
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
    public tag: Uint8Array
  ) {
    super(protectedHeaders, unprotectedHeaders);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.tag,
    ];
  }

  public get alg(): MacAlgorithms | undefined {
    return (
      (this.protectedHeaders.get(Headers.Algorithm) as MacAlgorithms) ||
      (this.unprotectedHeaders.get(Headers.Algorithm) as MacAlgorithms)
    );
  }

  public get algName(): SupportedMacAlg | undefined {
    return this.alg ? MacAlgorithmNames.get(this.alg) : undefined;
  }

  public hasSupportedAlg() {
    return !!this.algName;
  }

  static async create(
    protectedHeaders:
      | MacProtectedHeaders
      | ConstructorParameters<typeof MacProtectedHeaders>[0],
    unprotectedHeaders:
      | UnprotectedHeaders
      | ConstructorParameters<typeof UnprotectedHeaders>[0]
      | undefined,
    payload: Uint8Array,
    key: Uint8Array,
    ctx: { cose: Pick<MdocContext['cose'], 'mac0'> }
  ) {
    const wProtectedHeaders = MacProtectedHeaders.wrap(protectedHeaders);
    const wUnprotectedHeaders = UnprotectedHeaders.wrap(unprotectedHeaders);
    const encodedProtectedHeaders = cborEncode(wProtectedHeaders.esMap);

    const tag = await ctx.cose.mac0.sign({
      protectedHeaders,
      unprotectedHeaders,
      payload,
      key,
    });

    return new Mac0(
      encodedProtectedHeaders,
      wUnprotectedHeaders.esMap,
      payload,
      tag
    );
  }

  /**
   * Verifies the signature of this instance using the given key.
   *
   * @param {KeyLike | Uint8Array} key - The key to verify the signature with.
   * @param {VerifyOptions} [options] - Verify options
   * @param {MacAlgorithms[]} [options.algorithms] - List of allowed algorithms
   * @param {Uint8Array} [options.externalAAD] - External Additional Associated Data
   * @param {Uint8Array} [options.detachedPayload] - The detached payload to verify the signature with.
   * @returns {Boolean} - The result of the signature verification.
   */
  public async verify(
    key: Uint8Array,
    options: VerifyOptions | undefined,
    ctx: { cose: Pick<MdocContext['cose'], 'mac0'> }
  ): Promise<boolean> {
    const isValid = await ctx.cose.mac0.verify({
      key,
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payload,
      tag: this.tag,
      options,
    });
    return isValid;
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
