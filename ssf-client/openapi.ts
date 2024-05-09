import { createClient, defineConfig } from '@hey-api/openapi-ts';

(async () => {
  await createClient(defineConfig({
    client: 'axios',
    base: 'https://localhost:8001',
    debug: true,
    format: 'prettier',
    lint: 'eslint',
    input: '../openapi/ds-openapi.yml',
    output: './src/gen/clients/ds',
    // name: 'DSClient',
  }));
  
  await createClient(defineConfig({
    client: 'axios',
    base: 'https://localhost:8000',
    debug: true,
    format: 'prettier',
    lint: 'eslint',
    input: '../openapi/pki-openapi.yml',
    output: './src/gen/clients/pki',
    // name: 'PKIClient',
  }));
})();


