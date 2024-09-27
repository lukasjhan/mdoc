import * as v from 'valibot';
import { vJweHeader } from './jwe/v-jwe.js';
import { vJwsHeader } from './jws/v-jws.js';

export const vJoseProtectedHeader = v.intersect([vJwsHeader, vJweHeader]);
export type JoseProtectedHeader = v.InferInput<typeof vJoseProtectedHeader>;
