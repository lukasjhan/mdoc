import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from '../jwk/v-jwk.js';
import {
  vJwtPayload,
  vJwtVerifyOptions,
  vVerifyOptions,
} from '../jwt/index.js';
import { vJoseProtectedHeaderParameters } from '../v-jose.js';

export const vJoseJwsSignCompact = v.object({
  payload: v.string(),
  protectedHeader: vJoseProtectedHeaderParameters,
  jwk: vJwk,
});
export const vJoseJwsSignCompactOut = v.object({ jws: v.string() });
export type JoseJwsSignCompact = (
  input: v.InferInput<typeof vJoseJwsSignCompact>
) => MaybePromise<v.InferOutput<typeof vJoseJwsSignCompactOut>>;

export const vJoseJwsVerifyCompact = v.object({
  jws: v.string(),
  jwk: vJwk,
  options: v.optional(vVerifyOptions),
});
export const vJoseJwsVerifyCompactOut = v.object({
  payload: v.string(),
  protectedHeader: vJoseProtectedHeaderParameters,
});
export type JoseJwsVerifyCompact = (
  input: v.InferInput<typeof vJoseJwsVerifyCompact>
) => MaybePromise<v.InferOutput<typeof vJoseJwsVerifyCompactOut>>;

export const vJoseJwsSignJwt = v.object({
  payload: vJwtPayload,
  protectedHeader: vJoseProtectedHeaderParameters,
  jwk: vJwk,
});
export const vJoseJwsSignJwtOut = v.object({ jws: v.string() });
export type JoseJwsSignJwt = (
  input: v.InferInput<typeof vJoseJwsSignCompact>
) => MaybePromise<v.InferOutput<typeof vJoseJwsSignJwtOut>>;

export const vJoseJwsVerifyJwt = v.object({
  jws: v.string(),
  jwk: vJwk,
  options: v.optional(vJwtVerifyOptions),
});
export const vJoseJwsVerifyJwtOut = v.object({
  payload: vJwtPayload,
  protectedHeader: vJoseProtectedHeaderParameters,
});
export type JoseJwsVerifyJwt = (
  input: v.InferInput<typeof vJoseJwsVerifyCompact>
) => MaybePromise<v.InferInput<typeof vJoseJwsVerifyJwt>>;

export interface JoseJwsContext {
  jose: {
    jws: {
      signCompact: JoseJwsSignCompact;
      verifyCompact: JoseJwsVerifyCompact;
      signJwt: JoseJwsSignJwt;
      verifyJwt: JoseJwsVerifyJwt;
    };
  };
}
