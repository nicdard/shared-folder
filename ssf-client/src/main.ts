#!/usr/bin/env node

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
import { OpenAPI as pkiOpenAPI } from './gen/clients/pki';
import { OpenAPI as dsOpenAPI } from './gen/clients/ds';
import {
  loadDefaultCaTLSCredentialsInterceptor,
  loadDsTLSInterceptor,
} from './protocol/authentication';
import { startCLIRepl } from './repl';
import { createCLI } from './cli';

/**
 * The main function.
 * Set up the interceptors to handle TLS authentication and mutual TLS authentication.
 * Start the REPL with the CLI commands.
 */
async function main() {
  const [, , ...args] = process.argv;
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  if ((args.length > 0 && args[0] === '-i') || args[0] === '--interactive') {
    const cli = await createCLI();
    startCLIRepl(cli);
    return;
  } else {
    const cli = await createCLI(() => {
      // Do not exit the process.
    });
    await cli.parseAsync();
  }
}
main()
  .then(() => {
    // Empty
  })
  .catch((err) => console.error(err));
