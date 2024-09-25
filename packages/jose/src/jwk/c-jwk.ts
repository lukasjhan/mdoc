import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from './v-jwk.js';

export const vJoseJwkCalculateThumbprintUri = v.object({
  jwk: vJwk,
  digestAlgorithm: v.picklist(['sha256', 'sha384', 'sha512']),
});

export const vJoseJwkCalculateThumbprintUriOut = v.object({
  jwkThumbprintUri: v.string(),
});

export type JoseJwkCalculateThumbprintUri = (
  input: v.InferInput<typeof vJoseJwkCalculateThumbprintUri>
) => MaybePromise<v.InferOutput<typeof vJoseJwkCalculateThumbprintUriOut>>;

export interface JoseJwkContext {
  jose: {
    jwk: {
      calculateThumbprintUri: JoseJwkCalculateThumbprintUri;
    };
  };
}
