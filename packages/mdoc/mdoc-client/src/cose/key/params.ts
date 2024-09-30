/**
 * Creates a new map with the keys and values of the given map swapped.
 *
 * @param map {Map<K, V>} the original map
 * @returns {Map<V, K>} the new map
 */
export const reverseMap = <K, V>(map: Map<K, V>): Map<V, K> =>
  new Map(Array.from(map).map(([k, v]) => [v, k]));

export enum COSEKeyParam {
  KeyType = 1,
  KeyID = 2,
  Algorithm = 3,
  KeyOps = 4,
  Curve = -1,
  BaseIV = 5,
  x = -2,
  y = -3,
  d = -4,
  k = -1,
}

export enum JWKParam {
  kty = COSEKeyParam.KeyType,
  kid = COSEKeyParam.KeyID,
  alg = COSEKeyParam.Algorithm,
  key_ops = COSEKeyParam.KeyOps,
  base_iv = COSEKeyParam.BaseIV,
  crv = COSEKeyParam.Curve,
  x = COSEKeyParam.x,
  y = COSEKeyParam.y,
  d = COSEKeyParam.d,
  k = COSEKeyParam.k,
}

export const KTYSpecificJWKParams: {
  [k: string]: Map<number, string> | undefined;
} = {
  EC: new Map([
    [-1, 'crv'],
    [-2, 'x'],
    [-3, 'y'],
    [-4, 'd'],
  ]),
  OKP: new Map([
    [-1, 'crv'],
    [-2, 'x'],
    [-3, 'y'],
    [-4, 'd'],
  ]),
  oct: new Map([[-1, 'k']]),
};

export const KTYSpecificJWKParamsRev = Object.fromEntries(
  Object.entries(KTYSpecificJWKParams).map(([k, v]) => [k, reverseMap(v!)])
);
