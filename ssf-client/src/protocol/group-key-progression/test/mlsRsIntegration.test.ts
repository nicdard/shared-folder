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
import { string2ArrayBuffer } from '../../commonCrypto';
import { mlsCgkaInit, mls_example } from 'ssf';

it('Can create a client', async () => {
  await mls_example();
  await mlsCgkaInit(string2Uint8Array('alice'), string2Uint8Array('groupid'));
});

function string2Uint8Array(str: string) {
  return new Uint8Array(string2ArrayBuffer(str));
}
