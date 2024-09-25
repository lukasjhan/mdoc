import * as v from 'valibot';

import { BASE64_URL_REGEX } from '@protokoll/core';

export const isJws = (jws: string) => {
  const jwsParts = jws.split('.');
  return (
    jwsParts.length === 3 && jwsParts.every(part => BASE64_URL_REGEX.test(part))
  );
};

export const vJws = v.custom<string>(input => {
  if (typeof input !== 'string') return false;
  return isJws(input);
});
