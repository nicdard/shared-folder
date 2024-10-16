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
/** @type {import('ts-jest').JestConfigWithTsJest} */
// For a detailed explanation of each configuration property visit:
// https://jestjs.io/docs/configuration
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    roots: ['src/'],
    moduleDirectories: [
      'node_modules',
      'src',
    ],
    modulePathIgnorePatterns: ['<rootDir>/dist/'],
    resetMocks: true,
  
    // https://jestjs.io/docs/configuration#globals-object
    globals: {
      SOME_FEATURE_FLAG: true,
    },
    testTimeout: 1000000
  };
  