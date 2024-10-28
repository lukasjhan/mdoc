import baseConfig from '@ausweis/eslint/base';

/** @type {import('typescript-eslint').Config} */
export default [
  {
    ignores: ['dist/**'],
  },
  ...baseConfig,
];
