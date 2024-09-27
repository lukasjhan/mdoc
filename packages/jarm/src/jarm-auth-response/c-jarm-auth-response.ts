import * as v from 'valibot';

import type { MaybePromise, PickDeep } from '@protokoll/core';

import type { JoseContext } from '@protokoll/jose';
import {
  vJarmResponseMode,
  vOpenid4vpJarmResponseMode,
} from '../v-response-mode-registry.js';
import { vResponseType } from '../v-response-type-registry.js';
import type { JarmAuthResponse } from './v-jarm-auth-response.js';
import type { JarmDirectPostJwtResponse } from './v-jarm-direct-post-jwt-auth-response.js';

export const vAuthRequest = v.looseObject({
  state: v.optional(v.string()),
  response_mode: v.optional(
    v.union([vJarmResponseMode, vOpenid4vpJarmResponseMode])
  ),
  client_id: v.string(),
  response_type: vResponseType,
  client_metadata: v.optional(
    v.looseObject({
      jwks: v.optional(
        v.object({
          keys: v.array(
            v.looseObject({ kid: v.optional(v.string()), kty: v.string() })
          ),
        })
      ),
      jwks_uri: v.optional(v.string()),
    })
  ),
});

export type AuthRequest = v.InferInput<typeof vAuthRequest>;

export const vOAuthAuthRequestGetParamsOut = v.object({
  authRequest: vAuthRequest,
});

export type OAuthAuthRequestGetParamsOut = v.InferOutput<
  typeof vOAuthAuthRequestGetParamsOut
>;

export interface JarmDirectPostJwtAuthResponseValidationContext
  extends PickDeep<
    JoseContext,
    'jose.jwe.decryptCompact' | 'jose.jws.verifyJwt'
  > {
  openid4vp: {
    authRequest: {
      get: (
        input: JarmAuthResponse | JarmDirectPostJwtResponse
      ) => MaybePromise<OAuthAuthRequestGetParamsOut>;
    };
  };
}
