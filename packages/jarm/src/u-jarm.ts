import type { JWK } from '@protokoll/core';
import { fetchJWKS } from '@protokoll/core';
import * as v from 'valibot';
import { JarmDecryptionJwkExtractionError } from './e-jarm.js';
import { vAuthRequestParams } from './jarm-auth-response/c-jarm-auth-response.js';

export const extractDecryptionJwk = async (input: unknown) => {
  const vClientMetadata = vAuthRequestParams.entries.client_metadata;
  const parsedClientMetadata = v.safeParse(vClientMetadata, input);

  if (!parsedClientMetadata.success) {
    throw new JarmDecryptionJwkExtractionError({
      code: 'BAD_REQUEST',
      message: `Invalid client metadata format: ${JSON.stringify(v.flatten(parsedClientMetadata.issues))}`,
    });
  }

  const clientMetadata = parsedClientMetadata.output;
  let decJwk: JWK | undefined = clientMetadata.jwks?.keys.find(
    key => key.use === 'enc'
  );

  if (!decJwk && clientMetadata.jwks_uri) {
    const jwks = await fetchJWKS(clientMetadata.jwks_uri);
    decJwk = jwks.keys.find(key => key.use === 'enc');
  }

  if (!decJwk) {
    throw new JarmDecryptionJwkExtractionError({
      code: 'BAD_REQUEST',
      message: `No decryption key (key with use 'enc') found in client metadata.`,
    });
  }

  return input;
};
