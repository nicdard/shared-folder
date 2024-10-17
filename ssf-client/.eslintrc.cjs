// Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
// https://eslint.org/docs/latest/user-guide/configuring/configuration-files
// https://json.schemastore.org/eslintrc
module.exports = {
    root: true,
    env: {
      es6: true,
      browser: true,
      node: true,
      jest: true,
    },
    extends: [
      'eslint:recommended',
      'plugin:@typescript-eslint/recommended',
    ],
    parser: '@typescript-eslint/parser',
    plugins: ['@typescript-eslint'],
  
    parserOptions: {
      tsconfigRootDir: __dirname,
      sourceType: 'module',
    },
  
    // Project-specific rules
    rules: {
      // Example disabling a plugin rule
      // 0 = off, 1 = warn, 2 = error
      // '@typescript-eslint/no-unused-vars': 0,
    },
  
    overrides: [
      {
        files: ['src/**/*.ts'],
        parserOptions: {
          tsconfigRootDir: __dirname,
          project: ['./tsconfig.json'],
          sourceType: 'module',
        },
        extends: [
          'plugin:@typescript-eslint/recommended-requiring-type-checking'
        ],
      },
      {
        files: ['test/**/*.ts'],
        parserOptions: {
          tsconfigRootDir: __dirname,
          project: ['./test/tsconfig.json'],
          sourceType: 'module',
        },
      },
    ],
  };