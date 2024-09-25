import * as v from 'valibot';

import { vJweHeaderParameters } from './jwe/v-jwe.js';
import { vJwsHeaderParameters } from './jws/v-jws.js';

export const vProtectedHeaderParameters = v.intersect([
  vJwsHeaderParameters,
  vJweHeaderParameters,
]);
export type ProtectedHeaderParameters = v.InferInput<
  typeof vProtectedHeaderParameters
>;
