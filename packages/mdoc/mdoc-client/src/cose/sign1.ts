import type { MdocContext } from '../c-mdoc.js';
import { addExtension, cborEncode } from '../cbor/index.js';
import { ProtectedHeaders, UnprotectedHeaders } from './headers.js';
import { SignatureBase  } from './signature-base.js';
import type {VerifyOptions} from './signature-base.js';

export class Sign1 extends SignatureBase {
  constructor(
    protectedHeaders: Map<number, unknown> | Uint8Array,
    unprotectedHeaders: Map<number, unknown>,
    public readonly payload: Uint8Array,
    signature: Uint8Array
  ) {
    super(protectedHeaders, unprotectedHeaders, signature);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.signature,
    ];
  }

  /**
   *
   * Verifies the signature of this instance using the given key.
   *
   * @param key {KeyLike | Uint8Array | COSEVerifyGetKey} - The key to verify the signature with.
   * @param options {VerifyOptions} - Verify options
   * @param options.algorithms {Algorithms[]} - List of allowed algorithms
   * @param options.externalAAD {Uint8Array} - External Additional Associated Data
   * @param options.detachedPayload {Uint8Array} - The detached payload to verify the signature with.
   * @returns {Promise<void>}
   */
  public async verify(
    key: Uint8Array,
    options: VerifyOptions | undefined,
    ctx: { cose: Pick<MdocContext['cose'], 'sign1'> }
  ): Promise<boolean> {
    return await ctx.cose.sign1.verify({
      key,
      payload: this.payload,
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      signature: this.signature,
      options,
    });
  }

  static async sign(
    protectedHeaders: ProtectedHeaders,
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: Uint8Array,
    ctx: { cose: Pick<MdocContext['cose'], 'sign1'> }
  ) {
    const wProtectedHeaders = ProtectedHeaders.wrap(protectedHeaders);
    const encodedProtectedHeaders = cborEncode(wProtectedHeaders.esMap);
    const unprotectedHeadersMap =
      UnprotectedHeaders.wrap(unprotectedHeaders).esMap;

    const signature = await ctx.cose.sign1.sign({
      key,
      payload,
      protectedHeaders,
      unprotectedHeaders,
    });

    return new Sign1(
      encodedProtectedHeaders,
      unprotectedHeadersMap,
      payload,
      signature
    );
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
