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

export namespace JoseJwsSignCompact {
  export const vInput = v.object({
    payload: v.string(),
    protectedHeader: vCompactJwsHeader,
    jwk: vJwk,
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({
    jws: v.string(),
  });
  export type Out = v.InferOutput<typeof vOut>;
}
export type JoseJwsSignCompact = (
  input: JoseJwsSignCompact.Input
) => MaybePromise<JoseJwsSignCompact.Out>;

export namespace JoseJwsVerifyCompact {
  export const vInput = v.object({
    jws: v.string(),
    jwk: vJwk,
    options: v.optional(vVerifyOptions),
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({
    payload: v.string(),
    protectedHeader: vCompactJwsHeader,
  });
  export type Out = v.InferOutput<typeof vOut>;
}

export type JoseJwsVerifyCompact = (
  input: JoseJwsVerifyCompact.Input
) => MaybePromise<JoseJwsVerifyCompact.Out>;

export namespace JoseJwsSignJwt {
  export const vInput = v.object({
    payload: vJwtPayload,
    protectedHeader: vJwtHeader,
    jwk: vJwk,
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({ jws: v.string() });
  export type Out = v.InferOutput<typeof vOut>;
}

export type JoseJwsSignJwt = (
  input: JoseJwsSignJwt.Input
) => MaybePromise<JoseJwsSignJwt.Out>;

export namespace JoseJwsVerifyJwt {
  export const vInput = v.object({
    jws: v.string(),
    jwk: vJwk,
    options: v.optional(vJwtVerifyOptions),
  });
  export type Input = v.InferInput<typeof vInput>;
  export const vOut = v.object({
    payload: vJwtPayload,
    protectedHeader: vJwtHeader,
  });
  export type Out = v.InferOutput<typeof vOut>;
}

export type JoseJwsVerifyJwt = (
  input: JoseJwsVerifyJwt.Input
) => MaybePromise<JoseJwsVerifyJwt.Out>;

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
