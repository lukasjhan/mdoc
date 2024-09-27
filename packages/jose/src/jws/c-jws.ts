import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from '../jwk/v-jwk.js';
import {
  vJwtHeader,
  vJwtPayload,
  vJwtVerifyOptions,
  vVerifyOptions,
} from '../jwt/index.js';
import { vCompactJwsHeader } from './v-jws.js';

export const vJoseJwsSignCompactInput = v.object({
  payload: v.string(),
  protectedHeader: vCompactJwsHeader,
  jwk: vJwk,
});
export const vJoseJwsSignCompactOut = v.object({ jws: v.string() });
export type JoseJwsSignCompact = (
  input: v.InferInput<typeof vJoseJwsSignCompactInput>
) => MaybePromise<v.InferOutput<typeof vJoseJwsSignCompactOut>>;

export const vJoseJwsVerifyCompactInput = v.object({
  jws: v.string(),
  jwk: vJwk,
  options: v.optional(vVerifyOptions),
});
export const vJoseJwsVerifyCompactOut = v.object({
  payload: v.string(),
  protectedHeader: vCompactJwsHeader,
});
export type JoseJwsVerifyCompact = (
  input: v.InferInput<typeof vJoseJwsVerifyCompactInput>
) => MaybePromise<v.InferOutput<typeof vJoseJwsVerifyCompactOut>>;

export const vJoseJwsSignJwtInput = v.object({
  payload: vJwtPayload,
  protectedHeader: vJwtHeader,
  jwk: vJwk,
});
export const vJoseJwsSignJwtOut = v.object({ jws: v.string() });
export type JoseJwsSignJwt = (
  input: v.InferInput<typeof vJoseJwsSignJwtInput>
) => MaybePromise<v.InferOutput<typeof vJoseJwsSignJwtOut>>;

export const vJoseJwsVerifyJwtInput = v.object({
  jws: v.string(),
  jwk: vJwk,
  options: v.optional(vJwtVerifyOptions),
});
export const vJoseJwsVerifyJwtOut = v.object({
  payload: vJwtPayload,
  protectedHeader: vJwtHeader,
});
export type JoseJwsVerifyJwt = (
  input: v.InferInput<typeof vJoseJwsVerifyJwtInput>
) => MaybePromise<v.InferInput<typeof vJoseJwsVerifyJwtOut>>;

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
