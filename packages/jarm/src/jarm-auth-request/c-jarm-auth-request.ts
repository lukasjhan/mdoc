import type { PickDeep } from '@protokoll/core';
import type { JoseContext } from '@protokoll/jose';

export type JarmSendAuthRequestContext = PickDeep<
  JoseContext,
  'jose.jwe.encryptJwt' | 'jose.jws.signJwt' | 'jose.jwe.encryptCompact'
>;
