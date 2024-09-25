import * as v from 'valibot';

import type {
  CompactJWEHeaderParameters,
  JWK,
  JWTPayload,
  MaybePromise,
  ProtectedHeaderParameters,
} from '@protokoll/core';

import {
  vJarmResponseMode,
  vOpenid4vpJarmResponseMode,
} from '../v-response-mode-registry.js';
import { vResponseType } from '../v-response-type-registry.js';
import type { JarmAuthResponseParams } from './v-jarm-auth-response-params.js';
import type { JarmDirectPostJwtResponseParams } from './v-jarm-direct-post-jwt-auth-response-params.js';

export const vAuthRequestParams = v.looseObject({
  state: v.optional(v.string()),
  response_mode: v.optional(
    v.union([vJarmResponseMode, vOpenid4vpJarmResponseMode])
  ),
  client_id: v.string(),
  response_type: vResponseType,
  client_metadata: v.looseObject({
    jwks: v.optional(
      v.object({
        keys: v.array(
          v.looseObject({ kid: v.optional(v.string()), kty: v.string() })
        ),
      })
    ),
    jwks_uri: v.optional(v.string()),
  }),
});

export type AuthRequestParams = v.InferInput<typeof vAuthRequestParams>;

export const vOAuthAuthRequestGetParamsOut = v.object({
  authRequestParams: vAuthRequestParams,
});

export type OAuthAuthRequestGetParamsOut = v.InferOutput<
  typeof vOAuthAuthRequestGetParamsOut
>;

export type JoseJwsVerify = (input: {
  compact: string;
  jwk: JWK;
}) => MaybePromise<{
  payload: JWTPayload;
  protectedHeader: ProtectedHeaderParameters;
}>;

export type JoseJweEncrypt = (input: {
  plaintext: string;
  jwk: JWK;
}) => MaybePromise<{
  jwe: string;
}>;

export type JoseJweDecrypt = (input: {
  jwe: string;
  jwk: JWK;
}) => MaybePromise<{
  plaintext: string;
  protectedHeader: CompactJWEHeaderParameters;
}>;

export interface JarmDirectPostJwtAuthResponseValidationContext {
  openid4vp: {
    authRequest: {
      getParams: (
        input: JarmAuthResponseParams | JarmDirectPostJwtResponseParams
      ) => MaybePromise<OAuthAuthRequestGetParamsOut>;
    };
  };
  jose: {
    jwe: { decrypt: JoseJweDecrypt };
    jws: { verify: JoseJwsVerify };
  };
  wallet: {
    getJwk: (input: { kid: string }) => MaybePromise<{ jwk: JWK }>;
  };
}
