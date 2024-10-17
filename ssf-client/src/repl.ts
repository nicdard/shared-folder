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
import { Command } from '@commander-js/extra-typings';
import { start } from 'repl';
import { logout } from './protocol/authentication';

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
  repl.on('exit', () => {
    logout();
    process.exit();
  });
  return repl;
}
