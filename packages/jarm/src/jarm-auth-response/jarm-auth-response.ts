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
import type { JarmDirectPostJwtResponse } from '../index.js';
import type {
  AuthRequest,
  JarmDirectPostJwtAuthResponseValidationContext,
} from './c-jarm-auth-response.js';
import { vJarmAuthResponseError } from './v-jarm-auth-response.js';
import {
  jarmAuthResponseEncryptionOnlyValidate,
  vJarmEncrytedOnlyAuthResponse,
} from './v-jarm-direct-post-jwt-auth-response.js';

export interface JarmDirectPostJwtAuthResponseValidation {
  /**
   * The JARM response parameter conveyed either as url query param, fragment param, or application/x-www-form-urlencoded in the body of a post request
   */
  response: string;
}

const parseJarmAuthResponse = <
  Schema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>,
>(
  schema: Schema,
  response: unknown
) => {
  if (v.is(vJarmAuthResponseError, response)) {
    const errorResponseJson = JSON.stringify(response, undefined, 2);
    throw new JarmReceivedErrorResponse({
      code: 'PARSE_ERROR',
      message: `Received error response from authorization server. '${errorResponseJson}'`,
    });
  }

  return v.parse(schema, response);
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

  const { plaintext } = await ctx.jose.jwe.decryptCompact({
    jwe: response,
    jwk: { kid: responseProtectedHeader.kid, kty: 'auto' },
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

  let authResponse: JarmDirectPostJwtResponse;
  let authRequest: AuthRequest;

  if (responseIsSigned) {
    const jwsProtectedHeader = decodeProtectedHeader(decryptedResponse);
    const jwsPayload = decodeJwt(decryptedResponse);

    const schema = v.required(vJarmEncrytedOnlyAuthResponse, [
      'iss',
      'aud',
      'exp',
    ]);
    const response = parseJarmAuthResponse(schema, jwsPayload);
    ({ authRequest } = await ctx.openid4vp.authRequest.get(response));

    if (!jwsProtectedHeader.kid) {
      throw new JarmAuthResponseValidationError({
        message: `Jarm JWS is missing the protected header field 'kid'.`,
      });
    }

    await ctx.jose.jws.verifyJwt({
      jws: decryptedResponse,
      jwk: { kid: jwsProtectedHeader.kid, kty: 'auto' },
    });
    authResponse = response;
  } else {
    const jsonResponse: unknown = JSON.parse(decryptedResponse);
    authResponse = parseJarmAuthResponse(
      vJarmEncrytedOnlyAuthResponse,
      jsonResponse
    );
    ({ authRequest } = await ctx.openid4vp.authRequest.get(authResponse));
  }

  jarmAuthResponseEncryptionOnlyValidate({
    authRequest: authRequest,
    authResponse: authResponse,
  });

  let type: 'signed encrypted' | 'encrypted' | 'signed';
  if (responseIsSigned && responseIsEncrypted) type = 'signed encrypted';
  else if (responseIsEncrypted) type = 'encrypted';
  else type = 'signed';

  return { authRequest, authResponse, type };
};
