import * as v from 'valibot';
import { getSubtleCrypto } from './get-subtle-crypto.js';

export const vDigestAlgorithm = v.picklist(['sha256', 'sha384', 'sha512']);
export type DigestAlgorithm = v.InferOutput<typeof vDigestAlgorithm>;

export const digest = async (input: {
  algorithm: DigestAlgorithm;
  data: Uint8Array;
  crypto?: { subtle: SubtleCrypto };
}): Promise<Uint8Array> => {
  const { algorithm, data } = input;

  const subtleCrypto = getSubtleCrypto(input);
  const subtleDigest = `SHA-${algorithm.slice(-3)}`;
  return new Uint8Array(await subtleCrypto.digest(subtleDigest, data));
};
