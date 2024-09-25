import type * as jose from 'jose';
import { jwtDecode } from 'jwt-decode';
import * as v from 'valibot';
import { AusweisError, JwksExtractionError } from '../e-ausweis.js';

// https://base64.guru/standards/base64url
const BASE64_URL_REGEX =
  /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;

export const isJws = (jws: string) => {
  const jwsParts = jws.split('.');
  return (
    jwsParts.length === 3 && jwsParts.every(part => BASE64_URL_REGEX.test(part))
  );
};

export const isJwe = (jwe: string) => {
  const jweParts = jwe.split('.');
  return (
    jweParts.length === 5 && jweParts.every(part => BASE64_URL_REGEX.test(part))
  );
};

export const checkExp = (input: {
  exp: number;
  now?: number; // The number of milliseconds elapsed since midnight, January 1, 1970 Universal Coordinated Time (UTC).
  clockSkew?: number;
}) => {
  const { exp, now, clockSkew } = input;
  return exp < (now ?? Date.now() / 1000) - (clockSkew ?? 120);
};

export const decodeProtectedHeader = (
  jwt: string
): jose.ProtectedHeaderParameters => {
  return jwtDecode(jwt, { header: true });
};

export const decodeJwt = (jwt: string): jose.JWTPayload => {
  return jwtDecode(jwt, { header: false });
};

export type JWKS = jose.JSONWebKeySet;
export type JWK = jose.JWK;
export type JWTPayload = jose.JWTPayload;
export type CompactJWEHeaderParameters = jose.CompactJWEHeaderParameters;
export type ProtectedHeaderParameters = jose.ProtectedHeaderParameters;

/**
 * Fetches a JSON Web Key Set (JWKS) from the specified URI.
 *
 * @param jwksUri - The URI of the JWKS endpoint.
 * @returns A Promise that resolves to the JWKS object.
 * @throws Will throw an error if the fetch fails or if the response is not valid JSON.
 */
export async function joseFetchJWKS(
  jwksUri: string
): Promise<JWKS | undefined> {
  const response = await fetch(jwksUri, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new AusweisError({
      code: 'BAD_REQUEST',
      message: `HTTP error! status: ${response.status}`,
    });
  }

  const vJwks = v.looseObject({
    keys: v.array(
      v.looseObject({
        kid: v.optional(v.string()),
        kty: v.string(),
      })
    ),
  });

  const parsedJwks = v.safeParse(vJwks, await response.json());

  // Basic validation to ensure the response has a 'keys' array
  if (!parsedJwks.success) {
    throw new AusweisError({
      code: 'BAD_REQUEST',
      message: `Invalid JWKS format: missing or invalid "keys" array. ${JSON.stringify(v.flatten(parsedJwks.issues))}`,
    });
  }

  if (!parsedJwks.output.keys[0]) return undefined;
  return parsedJwks.output;
}

export const vJwksExtractable = v.looseObject({
  jwks: v.optional(
    v.object({
      keys: v.array(
        v.looseObject({ kid: v.optional(v.string()), kty: v.string() })
      ),
    })
  ),
  jwks_uri: v.optional(v.string()),
});

/**
 * Extracts JSON Web Key Set (JWKS) from the provided client metadata.
 * If a jwks field is provided, the JWKS will be extracted from the field.
 * If a jwks_uri is provided, the JWKS will be fetched from the URI.
 *
 * @param input - The client metadata input to be validated and parsed.
 * @returns A promise that resolves to the extracted JWKS or undefined.
 * @throws {JwksExtractionError} If the client metadata format is invalid or no decryption key is found.
 */
export const joseExtractJWKS = async (
  input: v.InferInput<typeof vJwksExtractable>
) => {
  const vClientMetadata = vJwksExtractable;
  const parsedClientMetadata = v.safeParse(vClientMetadata, input);

  if (!parsedClientMetadata.success) {
    throw new JwksExtractionError({
      code: 'BAD_REQUEST',
      message: `Invalid client metadata format: ${JSON.stringify(v.flatten(parsedClientMetadata.issues))}`,
    });
  }

  const clientMetadata = parsedClientMetadata.output;
  let jwks: JWKS | undefined = clientMetadata.jwks?.keys[0]
    ? clientMetadata.jwks
    : undefined;

  if (!jwks && clientMetadata.jwks_uri) {
    jwks = await joseFetchJWKS(clientMetadata.jwks_uri);
  }

  return jwks;
};
