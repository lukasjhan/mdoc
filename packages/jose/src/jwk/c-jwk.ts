import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from './v-jwk.js';

export namespace JoseJwkCalculateThumbprintUri {
  export const vInput = v.object({
    jwk: vJwk,
    digestAlgorithm: v.picklist(['sha256', 'sha384', 'sha512']),
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({
    jwkThumbprintUri: v.string(),
  });
  export type Out = v.InferOutput<typeof vOut>;
}

export type JoseJwkCalculateThumbprintUri = (
  input: JoseJwkCalculateThumbprintUri.Input
) => MaybePromise<JoseJwkCalculateThumbprintUri.Out>;

export interface JoseJwkContext {
  jose: {
    jwk: {
      calculateThumbprintUri: JoseJwkCalculateThumbprintUri;
    };
  };
}
