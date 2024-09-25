import type { MergeDeep } from '@protokoll/core';

import type { JoseJweContext, JoseJwkContext } from './index.js';
import type { JoseJwsContext } from './jws/c-jws.js';

export type JoseContext = MergeDeep<
  JoseJwkContext,
  MergeDeep<JoseJweContext, JoseJwsContext>
>;
