import type { JWK } from 'jose';
import isObject from './is-object.js';
import { jwkToKey } from './jwk-to-key.js';

/**
 * Imports a JWK to a runtime-specific key representation (KeyLike). Either the JWK "alg"
 * (Algorithm) Parameter, or the optional "alg" argument, must be present.
 *
 * Note: When the runtime is using {@link https://w3c.github.io/webcrypto/ Web Cryptography API} the
 * jwk parameters "use", "key_ops", and "ext" are also used in the resulting {@link !CryptoKey}.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/import'`.
 *
 * @example
 *
 * ```js
 * const ecPublicKey = await jose.importJWK(
 *   {
 *     crv: 'P-256',
 *     kty: 'EC',
 *     x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
 *     y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo',
 *   },
 *   'ES256',
 * )
 *
 * const rsaPublicKey = await jose.importJWK(
 *   {
 *     kty: 'RSA',
 *     e: 'AQAB',
 *     n: '12oBZRhCiZFJLcPg59LkZZ9mdhSMTKAQZYq32k_ti5SBB6jerkh-WzOMAO664r_qyLkqHUSp3u5SbXtseZEpN3XPWGKSxjsy-1JyEFTdLSYe6f9gfrmxkUF_7DTpq0gn6rntP05g2-wFW50YO7mosfdslfrTJYWHFhJALabAeYirYD7-9kqq9ebfFMF4sRRELbv9oi36As6Q9B3Qb5_C1rAzqfao_PCsf9EPsTZsVVVkA5qoIAr47lo1ipfiBPxUCCNSdvkmDTYgvvRm6ZoMjFbvOtgyts55fXKdMWv7I9HMD5HwE9uW839PWA514qhbcIsXEYSFMPMV6fnlsiZvQQ',
 *   },
 *   'PS256',
 * )
 * ```
 *
 * @param jwk JSON Web Key.
 * @param alg (Only effective in Web Crypto API runtimes) JSON Web Algorithm identifier to be used
 *   with the imported key. Default is the "alg" property on the JWK, its presence is only enforced
 *   in Web Crypto API runtimes. See
 *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
 */
export async function importJWK(jwk: JWK, alg?: string): Promise<CryptoKey> {
  if (!isObject(jwk)) {
    throw new TypeError('JWK must be an object');
  }

  alg ||= jwk.alg;

  switch (jwk.kty) {
    case 'oct':
      if (typeof jwk.k !== 'string' || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }

      if (!jwk.alg?.startsWith('HS')) {
        throw new Error('Invalid Key Input');
      }
      return crypto.subtle.importKey(
        'jwk',
        jwk,
        { hash: `SHA-${jwk.alg.slice(-3)}`, name: 'HMAC' },
        false,
        ['sign', 'verify']
      );

    case 'RSA':
      if (jwk.oth !== undefined) {
        throw new Error(
          'RSA JWK "oth" (Other Primes Info) Parameter value is not supported'
        );
      }
      break;
    case 'EC':
    case 'OKP':
      return jwkToKey({ ...jwk, alg });
  }

  throw new Error('Unsupported "kty" (Key Type) Parameter value');
}
