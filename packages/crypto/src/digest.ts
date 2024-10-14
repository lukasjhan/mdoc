import * as v from 'valibot';
import type { CryptoContext } from './c-crypto.js';
import { withCryptoContext } from './c-crypto.js';

export const vDigestAlgorithm = v.picklist(['sha256', 'sha384', 'sha512']);
export type DigestAlgorithm = v.InferOutput<typeof vDigestAlgorithm>;

export const digest = async (
  input: {
    algorithm: DigestAlgorithm;
    data: Uint8Array;
  },
  _ctx?: CryptoContext
): Promise<Uint8Array> => {
  const { algorithm, data } = input;

  const ctx = withCryptoContext(_ctx ?? {});
  const subtleDigest = `SHA-${algorithm.slice(-3)}`;
  return new Uint8Array(await ctx.crypto.subtle.digest(subtleDigest, data));
};
