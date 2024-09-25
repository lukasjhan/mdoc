import * as v from 'valibot';
import { JoseError, JoseJwksExtractionError } from '../e-jose.js';
import { vJwks, type Jwks } from './v-jwk.js';

/**
 * Fetches a JSON Web Key Set (JWKS) from the specified URI.
 *
 * @param jwksUri - The URI of the JWKS endpoint.
 * @returns A Promise that resolves to the JWKS object.
 * @throws Will throw an error if the fetch fails or if the response is not valid JSON.
 */
export async function joseJwksFetch(
  jwksUri: string
): Promise<Jwks | undefined> {
  const response = await fetch(jwksUri, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new JoseError({
      code: 'BAD_REQUEST',
      message: `HTTP error! status: ${response.status}`,
    });
  }

  const parsedJwks = v.safeParse(vJwks, await response.json());

  // Basic validation to ensure the response has a 'keys' array
  if (!parsedJwks.success) {
    throw new JoseError({
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
 * Extracts JSON Web Key Set (JWKS) from the provided metadata.
 * If a jwks field is provided, the JWKS will be extracted from the field.
 * If a jwks_uri is provided, the JWKS will be fetched from the URI.
 *
 * @param input - The metadata input to be validated and parsed.
 * @returns A promise that resolves to the extracted JWKS or undefined.
 * @throws {JoseJwksExtractionError} If the metadata format is invalid or no decryption key is found.
 */
export const joseJwksExtract = async (
  input: v.InferInput<typeof vJwksExtractable>
) => {
  const parsedMetadata = v.safeParse(vJwksExtractable, input);

  if (!parsedMetadata.success) {
    throw new JoseJwksExtractionError({
      code: 'BAD_REQUEST',
      message: `Invalid metadata format: ${JSON.stringify(v.flatten(parsedMetadata.issues))}`,
    });
  }

  const metadata = parsedMetadata.output;
  let jwks: Jwks | undefined = metadata.jwks?.keys[0]
    ? metadata.jwks
    : undefined;

  if (!jwks && metadata.jwks_uri) {
    jwks = await joseJwksFetch(metadata.jwks_uri);
  }

  return jwks;
};
