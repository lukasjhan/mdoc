import * as v from 'valibot';

import { JarmAuthResponseValidationError } from '../e-jarm.js';
import { vJarmAuthResponse } from './v-jarm-auth-response.js';

export const vJarmEncrytedOnlyAuthResponse = v.looseObject({
  ...v.omit(vJarmAuthResponse, ['iss', 'aud', 'exp']).entries,
  ...v.partial(v.pick(vJarmAuthResponse, ['iss', 'aud', 'exp'])).entries,

  vp_token: v.string(),
  presentation_submission: v.unknown(),
  nonce: v.optional(v.string()),
});

export type JarmDirectPostJwtResponse = v.InferInput<
  typeof vJarmEncrytedOnlyAuthResponse
>;

export const jarmAuthResponseEncryptionOnlyValidate = (input: {
  authRequest: { state?: string };
  authResponse: JarmDirectPostJwtResponse;
}) => {
  const { authRequest, authResponse } = input;

  // 2. The client obtains the state parameter from the JWT and checks its binding to the user agent. If the check fails, the client MUST abort processing and refuse the response.
  if (authRequest.state !== authResponse.state) {
    throw new JarmAuthResponseValidationError({
      message: `State missmatch between auth request '${authRequest.state}' and the jarm-auth-response.`,
    });
  }
};
