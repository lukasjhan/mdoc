export function subtleMapping(jwk: JsonWebKey): {
  algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  keyUsages: KeyUsage[];
} {
  let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  let keyUsages: KeyUsage[];

  switch (jwk.kty) {
    case 'RSA': {
      switch (jwk.alg) {
        case 'PS256':
        case 'PS384':
        case 'PS512':
          algorithm = { name: 'RSA-PSS', hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;
        case 'RS256':
        case 'RS384':
        case 'RS512':
          algorithm = {
            name: 'RSASSA-PKCS1-v1_5',
            hash: `SHA-${jwk.alg.slice(-3)}`,
          };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512':
          algorithm = {
            name: 'RSA-OAEP',
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`,
          };
          keyUsages = jwk.d ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey'];
          break;
        default:
          throw new Error(
            'Invalid or unsupported JWK "alg" (Algorithm) Parameter value'
          );
      }
      break;
    }
    case 'EC': {
      switch (jwk.alg) {
        case 'ES256':
          algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;
        case 'ES384':
          algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;
        case 'ES512':
          algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;
        case 'ECDH-ES':
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW':
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          algorithm = { name: 'ECDH', namedCurve: jwk.crv! };
          keyUsages = jwk.d ? ['deriveBits'] : [];
          break;
        default:
          throw new Error(
            'Invalid or unsupported JWK "alg" (Algorithm) Parameter value'
          );
      }
      break;
    }
    case 'OKP': {
      switch (jwk.alg) {
        case 'EdDSA':
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          algorithm = { name: jwk.crv! };
          keyUsages = jwk.d ? ['sign'] : ['verify'];
          break;
        case 'ECDH-ES':
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW':
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          algorithm = { name: jwk.crv! };
          keyUsages = jwk.d ? ['deriveBits'] : [];
          break;
        default:
          throw new Error(
            'Invalid or unsupported JWK "alg" (Algorithm) Parameter value'
          );
      }
      break;
    }
    default:
      throw new Error(
        'Invalid or unsupported JWK "kty" (Key Type) Parameter value'
      );
  }

  return { algorithm, keyUsages };
}

export const jwkToKey = async (input: {
  jwk: JsonWebKey;
  crypto?: { subtle: SubtleCrypto };
}): Promise<CryptoKey> => {
  const { jwk } = input;
  if (!jwk.alg) {
    throw new TypeError(
      '"alg" argument is required when "jwk.alg" is not present'
    );
  }

  const { algorithm, keyUsages } = subtleMapping(jwk);
  const rest: [
    RsaHashedImportParams | EcKeyAlgorithm | Algorithm,
    boolean,
    KeyUsage[],
  ] = [
    algorithm,
    jwk.ext ?? false,
    (jwk.key_ops as KeyUsage[] | undefined) ?? keyUsages,
  ];

  const keyData: JsonWebKey = { ...jwk };
  delete keyData.alg;
  delete keyData.use;
  const subtleCrypto = input.crypto?.subtle ?? crypto.subtle;

  return subtleCrypto.importKey('jwk', keyData, ...rest);
};
