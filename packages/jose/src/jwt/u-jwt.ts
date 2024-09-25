import type { JwtPayload } from 'jwt-decode';
import { jwtDecode } from 'jwt-decode';

import type { ProtectedHeaderParameters } from '../v-protected-header.js';

export const decodeProtectedHeader = (
  jwt: string
): ProtectedHeaderParameters => {
  return jwtDecode(jwt, { header: true });
};

export const decodeJwt = (jwt: string): JwtPayload => {
  return jwtDecode(jwt, { header: false });
};
