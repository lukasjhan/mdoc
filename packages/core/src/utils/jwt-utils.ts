import type * as jose from 'jose';
import { jwtDecode } from 'jwt-decode';

// https://base64.guru/standards/base64url
const BASE64_URL_REGEX =
  /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;

export const isJws = (jws: string) => {
  const jwsParts = jws.split('.');
  return (
    jwsParts.length === 3 && jwsParts.every(part => BASE64_URL_REGEX.test(part))
  );
};

export const isJwe = (jwe: string) => {
  const jweParts = jwe.split('.');
  return (
    jweParts.length === 5 &&
    jweParts.every(part => BASE64_URL_REGEX.test(part) || part === '') // TODO: WHY IS THIS NOT WORKING
  );
};

export const checkExp = (input: {
  exp: number;
  now?: number; // The number of milliseconds elapsed since midnight, January 1, 1970 Universal Coordinated Time (UTC).
  clockSkew?: number;
}) => {
  const { exp, now, clockSkew } = input;
  return exp < (now ?? Date.now() / 1000) + (clockSkew ?? 120);
};

export const decodeProtectedHeader = (
  jwt: string
): jose.ProtectedHeaderParameters => {
  return jwtDecode(jwt, { header: true });
};

export const decodeJwt = (jwt: string): jose.JWTPayload => {
  return jwtDecode(jwt, { header: false });
};

export type JSONWebKeySet = jose.JSONWebKeySet;
export type JWK = jose.JWK;
export type JWTPayload = jose.JWTPayload;
export type CompactJWEHeaderParameters = jose.CompactJWEHeaderParameters;
export type ProtectedHeaderParameters = jose.ProtectedHeaderParameters;
