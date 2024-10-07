import { Command } from '@commander-js/extra-typings';
import { start } from 'repl';
import { protocolClient } from './protocol/protocolCommon';

/**
 * Start the CLI REPL.
 */
export function startCLIRepl(program: Command) {
  const repl = start({
    prompt: 'ssf> ',
    ignoreUndefined: true,
    eval: (cmd, context, filename, callback) => {
      const args = cmd.trim().split(' ');
      // Do not use argv arguments.
      program
        .parseAsync(args, { from: 'user' })
        .then(() => callback(null, undefined))
        .catch(() => callback(null, undefined));
      // TODO: Add here notification processing.
    },
  });
  repl.on('exit', () => { process.exit()})
  return repl;
}
