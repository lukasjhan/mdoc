import { createDefaultEsmPreset, type JestConfigWithTsJest } from 'ts-jest';

const defaultEsmPreset = createDefaultEsmPreset();

const jestConfig: JestConfigWithTsJest = {
  // [...]
  ...defaultEsmPreset,
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  testMatch: ['**/__tests__/**/*.tests.ts'],
  globals: {
    'ts-jest': {
      tsconfig: {
        verbatimModuleSyntax: false,
      },
    },
  },
};

export default jestConfig;
