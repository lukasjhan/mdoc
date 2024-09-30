import * as v from 'valibot';
import {
  vJarmResponseMode,
  vOpenid4vpJarmResponseMode,
} from './v-response-mode-registry';
import { vResponseType } from './v-response-type-registry';

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
