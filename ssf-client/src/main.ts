#!/usr/bin/env node

import { OpenAPI as pkiOpenAPI } from './gen/clients/pki';
import { OpenAPI as dsOpenAPI } from './gen/clients/ds';
import {
  loadDefaultCaTLSCredentialsInterceptor,
  loadDsTLSInterceptor,
} from './authentication';
import { startCLIRepl } from './repl';
import { Protocol, createCLI } from './cli';
import { GRaPPA } from './protocol/group-key-progression/grappa';

/**
 * The main function.
 * Set up the interceptors to handle TLS authentication and mutual TLS authentication.
 * Start the REPL with the CLI commands.
 */
async function main() {
  const [, , ...args] = process.argv;
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  let protocol: Protocol = 'baseline';
  if (args.length > 0) {
    if (args[0] == 'baseline' || args[0] === 'GRaPPA') {
      protocol = args[0]
    } else {
      throw new Error("Only GRaPPA and baseline available, using baseline as a default");
    }
  }
  if (((args.length === 1 && args[0] === '-i') || args[0] === '--interactive') ||
    (args.length > 1 && args[1] === '-i' || args[1] === '--interactive')) {
    const cli = await createCLI(protocol);
    startCLIRepl(cli);
    return;
  } else {
    const cli = await createCLI(protocol, () => {
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
