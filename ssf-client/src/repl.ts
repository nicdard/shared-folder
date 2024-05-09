import { Command } from '@commander-js/extra-typings';
import { start } from 'repl';

/**
 * Start the CLI REPL.
 */
export function startCLIRepl(program: Command) {
  start({
    prompt: 'ssf> ',
    ignoreUndefined: true,
    eval: (cmd, context, filename, callback) => {
      const args = cmd.trim().split(' ');
      // Do not use argv arguments.
      program
        .parseAsync(args, { from: 'user' })
        .then(() => callback(null, undefined))
        .catch(() => callback(null, undefined));
    },
  });
}
