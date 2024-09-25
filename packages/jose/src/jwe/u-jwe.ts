import * as v from 'valibot';

import { BASE64_URL_REGEX } from '@protokoll/core';

export const isJwe = (jwe: string) => {
  const jweParts = jwe.split('.');
  return (
    jweParts.length === 5 && jweParts.every(part => BASE64_URL_REGEX.test(part))
  );
};

export const vJwe = v.custom<string>(input => {
  if (typeof input !== 'string') return false;
  return isJwe(input);
});
