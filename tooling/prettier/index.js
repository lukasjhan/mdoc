/** @typedef {import("prettier").Config} PrettierConfig */

/** @type { PrettierConfig  } */
const config = {
  plugins: ['prettier-plugin-organize-imports'],
  // https://github.com/nodejs/nodejs.org/
  singleQuote: true,
  trailingComma: 'es5',
  arrowParens: 'avoid',
};

export default config;
