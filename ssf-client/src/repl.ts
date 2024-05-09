import { Command } from '@commander-js/extra-typings';
import { start } from 'repl';

/**
 * Start the CLI REPL.
 */
export function startCLIRepl(program: Command) {
    start({
        prompt: 'ssf> ',
        ignoreUndefined: true,
        eval: async (cmd, context, filename, callback) => {
          const args = cmd.trim().split(' ');
          try {
            // Do not use argv arguments.
            await program.parseAsync(args, { from: 'user' });
            callback(null, undefined);              
          } catch (err) {                            
            callback(null, undefined);
          }
        }
    })
}