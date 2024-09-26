import * as v from 'valibot';

import {
  decodeJwt,
  decodeProtectedHeader,
  isJwe,
  isJws,
} from '@protokoll/jose';

import {
  JarmAuthResponseValidationError,
  JarmReceivedErrorResponse,
} from '../e-jarm.js';
import type { JarmDirectPostJwtResponseParams } from '../index.js';
import type {
  AuthRequestParams,
  JarmDirectPostJwtAuthResponseValidationContext,
} from './c-jarm-auth-response.js';
import { vJarmAuthResponseErrorParams } from './v-jarm-auth-response-params.js';
import {
  jarmAuthResponseDirectPostValidateParams,
  vJarmDirectPostJwtParams,
} from './v-jarm-direct-post-jwt-auth-response-params.js';

export interface JarmDirectPostJwtAuthResponseValidation {
  /**
   * The JARM response parameter conveyed either as url query param, fragment param, or application/x-www-form-urlencoded in the body of a post request
   */
  response: string;
}

const parseJarmAuthResponseParams = (responseParams: unknown) => {
  if (v.is(vJarmAuthResponseErrorParams, responseParams)) {
    const errorResponseJson = JSON.stringify(responseParams, undefined, 2);
    throw new JarmReceivedErrorResponse({
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
      message: `Jarm JWE is missing the protected header field 'kid'.`,
    });
  }

  const { jwk } = await ctx.wallet.getJwk({ kid: responseProtectedHeader.kid });
  const { plaintext } = await ctx.jose.jwe.decryptCompact({
    jwe: response,
    jwk,
  });

  return plaintext;
};

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export const jarmAuthResponseDirectPostJwtValidate = async (
  input: JarmDirectPostJwtAuthResponseValidation,
  ctx: JarmDirectPostJwtAuthResponseValidationContext
) => {
  const { response } = input;

  const responseIsEncrypted = isJwe(response);
  const decryptedResponse = responseIsEncrypted
    ? await decryptJarmAuthResponse(input, ctx)
    : response;

  const responseIsSigned = isJws(decryptedResponse);
  if (!responseIsEncrypted && !responseIsSigned) {
    throw new JarmAuthResponseValidationError({
      message:
        'Jarm Auth Response must be either encrypted, signed, or signed and encrypted.',
    });
  }

  let authResponseParams: JarmDirectPostJwtResponseParams;
  let authRequestParams: AuthRequestParams;

  if (responseIsSigned) {
    const jwsProtectedHeader = decodeProtectedHeader(decryptedResponse);
    const jwsPayload = decodeJwt(decryptedResponse);

    authResponseParams = parseJarmAuthResponseParams(jwsPayload);
    ({ authRequestParams } =
      await ctx.openid4vp.authRequest.getParams(authResponseParams));

    if (!jwsProtectedHeader.kid) {
      throw new JarmAuthResponseValidationError({
        message: `Jarm JWS is missing the protected header field 'kid'.`,
      });
    }

    const { jwk } = await ctx.wallet.getJwk({ kid: jwsProtectedHeader.kid });
    await ctx.jose.jws.verifyJwt({ jws: decryptedResponse, jwk });
  } else {
    const jsonResponse: unknown = JSON.parse(decryptedResponse);
    authResponseParams = parseJarmAuthResponseParams(jsonResponse);
    ({ authRequestParams } =
      await ctx.openid4vp.authRequest.getParams(authResponseParams));
  }

  jarmAuthResponseDirectPostValidateParams({
    authRequestParams,
    authResponseParams,
  });

  let type: 'signed encrypted' | 'encrypted' | 'signed';
  if (responseIsSigned && responseIsEncrypted) type = 'signed encrypted';
  else if (responseIsEncrypted) type = 'encrypted';
  else type = 'signed';

  return {
    authRequestParams,
    authResponseParams,
    type,
  };
};
