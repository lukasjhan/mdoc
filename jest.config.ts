import { createDefaultEsmPreset, type JestConfigWithTsJest } from 'ts-jest';

const defaultEsmPreset = createDefaultEsmPreset();

const jestConfig: JestConfigWithTsJest = {
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    // '^.+\\.[tj]sx?$' to process ts,js,tsx,jsx with `ts-jest`
    // '^.+\\.m?[tj]sx?$' to process ts,js,tsx,jsx,mts,mjs,mtsx,mjsx with `ts-jest`
    '^.+\\.[jt]sx?$': [
      'ts-jest',
      {
        useESM: true,
      },
    ],
  },
  testMatch: ['**/__tests__/**/*.tests.ts'],
};

export default jestConfig;
