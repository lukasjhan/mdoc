import * as v from 'valibot';

import { checkExp, vJwtPayload } from '@protokoll/jose';
import { JarmAuthResponseValidationError } from '../e-jarm.js';

export const vJarmAuthResponseError = v.looseObject({
  error: v.string(),
  state: v.optional(v.string()),

  error_description: v.pipe(
    v.optional(v.string()),
    v.description(
      'Text providing additional information, used to assist the client developer in understanding the error that occurred.'
    )
  ),

  error_uri: v.pipe(
    v.optional(v.pipe(v.string(), v.url())),
    v.description(
      'A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error'
    )
  ),
});

export const vJarmAuthResponse = v.looseObject({
  /**
   * iss: The issuer URL of the authorization server that created the response
   * aud: The client_id of the client the response is intended for
   */
  ...v.required(vJwtPayload, ['iss', 'aud', 'exp']).entries,
  state: v.optional(v.string()), // TODO: extend AuthResponseParams instead
});

export type JarmAuthResponse = v.InferInput<typeof vJarmAuthResponse>;

export const validateJarmAuthResponse = (input: {
  authRequest: { client_id: string; state?: string };
  authResponse: JarmAuthResponse;
}) => {
  const { authRequest, authResponse } = input;
  // 2. The client obtains the state parameter from the JWT and checks its binding to the user agent. If the check fails, the client MUST abort processing and refuse the response.
  if (authRequest.state !== authResponse.state) {
    throw new JarmAuthResponseValidationError({
      message: `State missmatch in jarm-auth-response. Expected '${authRequest.state}' received '${authRequest.state}'.`,
    });
  }

  // 4. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  if (authRequest.client_id !== authResponse.aud) {
    throw new JarmAuthResponseValidationError({
      message: `Invalid audience in jarm-auth-response. Expected '${authRequest.client_id}' received '${JSON.stringify(authResponse.aud)}'.`,
    });
  }

  // 5. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // 120 seconds clock skew
  if (checkExp({ exp: authResponse.exp })) {
    throw new JarmAuthResponseValidationError({
      message: `The '${authRequest.state}' and the jarm-auth-response.`,
    });
  }
};
