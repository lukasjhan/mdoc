import type { JwtPayload } from 'jwt-decode';
import { jwtDecode } from 'jwt-decode';

import type { JoseProtectedHeaderParameters } from '../v-jose.js';

export const decodeProtectedHeader = (
  jwt: string
): JoseProtectedHeaderParameters => {
  return jwtDecode(jwt, { header: true });
};

export const decodeJwt = (jwt: string): JwtPayload => {
  return jwtDecode(jwt, { header: false });
};

export const checkExp = (input: {
  exp: number;
  now?: number; // The number of milliseconds elapsed since midnight, January 1, 1970 Universal Coordinated Time (UTC).
  clockSkew?: number;
}) => {
  const { exp, now, clockSkew } = input;
  return exp < (now ?? Date.now() / 1000) - (clockSkew ?? 120);
};
