#!/usr/bin/env node

import { OpenAPI as pkiOpenAPI } from './gen/clients/pki';
import { OpenAPI as dsOpenAPI } from './gen/clients/ds';
import {
  loadDefaultCaTLSCredentialsInterceptor,
  loadDsTLSInterceptor,
} from './authentication';
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
