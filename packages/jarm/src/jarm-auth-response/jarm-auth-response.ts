import * as v from 'valibot';

import {
  decodeJwt,
  decodeProtectedHeader,
  isJwe,
  isJws,
} from '@protokoll/core';

import {
  JarmAuthResponseValidationError,
  JarmErrorResponseError,
} from '../e-jarm.js';
import type { JarmDirectPostJwtResponseParams } from '../index.js';
import {
  validateJarmDirectPostJwtAuthResponseParams,
  vJarmAuthResponseErrorParams,
  vJarmDirectPostJwtParams,
} from '../index.js';
import type {
  AuthRequestParams,
  JarmDirectPostJwtAuthResponseValidationContext,
} from './c-jarm-auth-response.js';

export interface JarmDirectPostJwtAuthResponseValidation {
  /**
   * The JARM response parameter conveyed either as url query param, fragment param, or application/x-www-form-urlencoded in the body of the post request
   */
  response: string;
}

const parseJarmAuthResponseParams = (responseParams: unknown) => {
  if (v.is(vJarmAuthResponseErrorParams, responseParams)) {
    const errorResponseJson = JSON.stringify(responseParams, undefined, 2);
    throw new JarmErrorResponseError({
      code: 'PARSE_ERROR',
      message: `Received error response from authorization server. '${errorResponseJson}'`,
    });
  }

  return v.parse(vJarmDirectPostJwtParams, responseParams);
};

const decryptJarmAuthResponse = async (
  input: { response: string },
  ctx: JarmDirectPostJwtAuthResponseValidationContext
) => {
  const { response } = input;

  const responseProtectedHeader = decodeProtectedHeader(response);
  if (!responseProtectedHeader.kid) {
    throw new JarmAuthResponseValidationError({
      code: 'BAD_REQUEST',
      message: `Jarm JWE is missing the protected header field 'kid'.`,
    });
  }

  const { jwk } = await ctx.wallet.getJwk({ kid: responseProtectedHeader.kid });
  const { plaintext } = await ctx.jose.jwe.decrypt({ jwe: response, jwk });

  return plaintext;
};

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export const validateJarmDirectPostJwtResponse = async (
  input: JarmDirectPostJwtAuthResponseValidation,
  ctx: JarmDirectPostJwtAuthResponseValidationContext
) => {
  const { response } = input;

  if (!isJws(response) && !isJwe(response)) {
    throw new JarmAuthResponseValidationError({
      code: 'BAD_REQUEST',
      message:
        'Jarm Auth Response must be either encrypted, signed, or signed and encrypted.',
    });
  }

  const decryptedResponse = isJwe(response)
    ? await decryptJarmAuthResponse(input, ctx)
    : response;

  let authResponseParams: JarmDirectPostJwtResponseParams;
  let authRequestParams: AuthRequestParams;

  if (isJws(decryptedResponse)) {
    const jwsProtectedHeader = decodeProtectedHeader(decryptedResponse);
    const jwsPayload = decodeJwt(decryptedResponse);

    authResponseParams = parseJarmAuthResponseParams(jwsPayload);
    ({ authRequestParams } =
      await ctx.openid4vp.authRequest.getParams(authResponseParams));

    if (!jwsProtectedHeader.kid) {
      throw new JarmAuthResponseValidationError({
        code: 'BAD_REQUEST',
        message: `Jarm JWS is missing the protected header field 'kid'.`,
      });
    }

    const jwk = authRequestParams.client_metadata.jwks?.keys.find(
      key => key.kid === jwsProtectedHeader.kid
    );

    if (!jwk) {
      throw new JarmAuthResponseValidationError({
        code: 'BAD_REQUEST',
        cause:
          'Could not determine the signature verification JWK from the client_metadata for the Jarm Response.',
      });
    }

    await ctx.jose.jws.verify({ compact: response, jwk });
  } else {
    const jsonResponse: unknown = JSON.parse(decryptedResponse);
    authResponseParams = parseJarmAuthResponseParams(jsonResponse);
    ({ authRequestParams } =
      await ctx.openid4vp.authRequest.getParams(authResponseParams));
  }

  // TODO: MUST WE CHECK WHEATHER THE KEY USED TO DECRYPT THE ACTUAL RESPONSE WAS CONVEYED IN THE METADATA?

  validateJarmDirectPostJwtAuthResponseParams({
    authRequestParams,
    authResponseParams,
  });

  return { authRequestParams, authResponseParams };
};
