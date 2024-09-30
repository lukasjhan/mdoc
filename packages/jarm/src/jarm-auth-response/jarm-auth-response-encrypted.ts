import * as v from 'valibot';

import type { JoseContext } from '@protokoll/jose';
import {
  decodeJwt,
  decodeProtectedHeader,
  isJwe,
  isJws,
} from '@protokoll/jose';

import type { MaybePromise, PickDeep } from '@protokoll/core';
import {
  JarmAuthResponseValidationError,
  JarmReceivedErrorResponse,
} from '../e-jarm.js';
import type { JarmAuthResponse, JarmAuthResponseEncrypted } from '../index.js';
import type { OAuthAuthRequestGetParamsOut } from '../v-auth-request.js';
import { vAuthRequest } from '../v-auth-request.js';
import {
  jarmAuthResponseEncryptedValidate,
  vJarmAuthResponseEncrypted,
  vJarmAuthResponseEncrypted as vJarmEncryptedOnlyAuthResponse,
} from './v-jarm-auth-response-encrypted.js';
import { vJarmAuthResponseError } from './v-jarm-auth-response.js';

export namespace JarmAuthResponseEncryptedHandle {
  export const vInput = v.object({
    /**
     * The JARM response parameter conveyed either as url query param, fragment param, or application/x-www-form-urlencoded in the body of a post request
     */
    response: v.string(),
  });
  export type Input = v.InferOutput<typeof vInput>;

  export const vOut = v.object({
    authRequest: vAuthRequest,
    authResponse: vJarmAuthResponseEncrypted,
    type: v.picklist(['signed encrypted', 'encrypted', 'signed']),
  });
  export type Out = v.InferOutput<typeof vOut>;

  export interface Context
    extends PickDeep<
      JoseContext,
      'jose.jwe.decryptCompact' | 'jose.jws.verifyJwt'
    > {
    openid4vp: {
      authRequest: {
        get: (
          input: JarmAuthResponse | JarmAuthResponseEncrypted
        ) => MaybePromise<OAuthAuthRequestGetParamsOut>;
      };
    };
  }
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
  ctx: JarmAuthResponseEncryptedHandle.Context
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
export const jarmAuthResponseEncryptedHandle = async (
  input: JarmAuthResponseEncryptedHandle.Input,
  ctx: JarmAuthResponseEncryptedHandle.Context
): Promise<JarmAuthResponseEncryptedHandle.Out> => {
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

  let authResponse: JarmAuthResponseEncrypted;
  let authRequest: v.InferOutput<typeof vAuthRequest>;

  if (responseIsSigned) {
    const jwsProtectedHeader = decodeProtectedHeader(decryptedResponse);
    const jwsPayload = decodeJwt(decryptedResponse);
    const schema = v.required(vJarmEncryptedOnlyAuthResponse, [
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
      vJarmEncryptedOnlyAuthResponse,
      jsonResponse
    );
    ({ authRequest } = await ctx.openid4vp.authRequest.get(authResponse));
  }

  jarmAuthResponseEncryptedValidate({ authRequest, authResponse });

  let type: 'signed encrypted' | 'encrypted' | 'signed';
  if (responseIsSigned && responseIsEncrypted) type = 'signed encrypted';
  else if (responseIsEncrypted) type = 'encrypted';
  else type = 'signed';

  return { authRequest, authResponse, type };
};
