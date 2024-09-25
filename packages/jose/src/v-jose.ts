import * as v from 'valibot';
import { vJweHeaderParameters } from './jwe/v-jwe.js';
import { vJwsHeaderParameters } from './jws/v-jws.js';

export const vJoseProtectedHeaderParameters = v.intersect([
  vJwsHeaderParameters,
  vJweHeaderParameters,
]);
export type JoseProtectedHeaderParameters = v.InferInput<
  typeof vJoseProtectedHeaderParameters
>;
