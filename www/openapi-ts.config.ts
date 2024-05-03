import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  base: 'https://localhost:8000/',
  debug: true,
  format: 'prettier',
  lint: 'eslint',
  input: '../openapi/pki-openapi.yml',
  output: './src/gen/pkiclient',
});
