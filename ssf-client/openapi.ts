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
import { createClient, defineConfig } from '@hey-api/openapi-ts';

(async () => {
  await createClient(
    defineConfig({
      client: 'axios',
      base: 'https://localhost:8001',
      debug: true,
      format: 'prettier',
      lint: 'eslint',
      input: '../openapi/ds-openapi.yml',
      output: './src/gen/clients/ds',
      // name: 'DSClient',
    })
  );

  await createClient(
    defineConfig({
      client: 'axios',
      base: 'https://localhost:8000',
      debug: true,
      format: 'prettier',
      lint: 'eslint',
      input: '../openapi/pki-openapi.yml',
      output: './src/gen/clients/pki',
      // name: 'PKIClient',
    })
  );
})();
