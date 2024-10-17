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
import {
  createCLI,
  dsCreateFolderAction,
  dsListFoldersAction,
  dsShareFolderAction,
  dsSyncAction,
  pkiCurrentAction,
  pkiSwitchAction,
} from '../cli';
import { crypto } from '../protocol/commonCrypto';
import { OpenAPI as pkiOpenAPI } from '../gen/clients/pki';
import { OpenAPI as dsOpenAPI } from '../gen/clients/ds';
import { loadDefaultCaTLSCredentialsInterceptor } from '../protocol/authentication';
import { loadDsTLSInterceptor } from '../protocol/authentication';
import fs = require('fs');
import fspromise = require('fs/promises');

const FILE_PATH = './README.md';
const FILENAME = 'R.md';
const DOWNLOAD_PATH = 'R.tmp';

function generateClientRandomIdentity() {
  return crypto.randomUUID() + '@test.com';
}

it('Cli-int-tests 2.', async () => {
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  const cli = await createCLI();
  const clients = [...Array(2).keys()].map(generateClientRandomIdentity);
  // It's reasonable that we do not do the following concurrently, as the client
  // will only do it once at a time when a user is using it.
  for (const client of clients) {
    await cli.parseAsync(['pki', 'create', client], { from: 'user' });
    await cli.parseAsync(['ds', 'register', client], { from: 'user' });
  }
  const current = await pkiCurrentAction();
  const creator1 = current[0];
  expect(creator1).toEqual(clients[clients.length - 1]);
  const others = clients.slice(0, -1);
  expect(others).toHaveLength(clients.length - 1);
  // Create a folder where current is admin.
  const folder = (await dsCreateFolderAction()).toString();
  console.warn('Folder created:', folder);
  // Share the folder with all other clients.
  for (const client of others) {
    await cli.parseAsync(['ds', 'share-folder', folder, client], {
      from: 'user',
    });
  }
  console.warn('Folder shared with all clients.');
  // Verify that all clients see the folder.
  for (const client of clients) {
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const folders = await dsListFoldersAction();
    expect(folders).toContain(Number(folder));
    expect(folders.length).toEqual(1);
  }
  console.warn('All clients see the folder.');

  // Add a member as admin, then remove it.
  const adminMember = generateClientRandomIdentity();
  await cli.parseAsync(['pki', 'create', adminMember], { from: 'user' });
  await cli.parseAsync(['ds', 'register', adminMember], { from: 'user' });
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  await cli.parseAsync(['ds', 'share-folder', folder, adminMember], {
    from: 'user',
  });
  await cli.parseAsync(['ds', 'add-admin', folder, adminMember], {
    from: 'user',
  });
  // Verify that the member is an admin.
  await cli.parseAsync(['pki', 'switch', adminMember], { from: 'user' });
  const role1 = await dsSyncAction(folder);
  expect(role1).toEqual('admin');
  // Now remove the admin privileges.
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  await cli.parseAsync(['ds', 'remove-admin', folder, adminMember], {
    from: 'user',
  });
  // Verify that the member is still a member but not an admin.
  await cli.parseAsync(['pki', 'switch', adminMember], { from: 'user' });
  const role2 = await dsSyncAction(folder);
  expect(role2).toEqual('member');
  // Clean up.
  // Remove all other members from the folder.
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  for (const client of others) {
    await cli.parseAsync(['ds', 'remove-member', folder, client], {
      from: 'user',
    });
  }
  // Sync other clients
  for (const client of others) {
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role = await dsSyncAction(folder);
    expect(role).toBeUndefined();
  }
});

it('Cli-int-tests 3.', async () => {
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  const cli = await createCLI();
  // With 2 users it does work.
  const clients = [...Array(3).keys()].map(generateClientRandomIdentity);
  // It's reasonable that we do not do the following concurrently, as the client
  // will only do it once at a time when a user is using it.
  for (const client of clients) {
    await cli.parseAsync(['pki', 'create', client], { from: 'user' });
    await cli.parseAsync(['ds', 'register', client], { from: 'user' });
  }
  const current = await pkiCurrentAction();
  const creator1 = current[0];
  expect(creator1).toEqual(clients[clients.length - 1]);
  const others = clients.slice(0, clients.length - 1);
  expect(others).toHaveLength(clients.length - 1);
  // Create a folder where current is admin.
  const folder = (await dsCreateFolderAction()).toString();
  console.log('Folder created:', folder);
  // Share the folder with all other clients.
  for (const client of others) {
    await cli.parseAsync(['ds', 'share-folder', folder, client], {
      from: 'user',
    });
  }
  console.info('Folder shared with all clients.');
  // Verify that all clients see the folder.
  for (const client of clients) {
    console.log('Switching to client:', client);
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const folders = await dsListFoldersAction();
    expect(folders).toContain(Number(folder));
    expect(folders.length).toEqual(1);
  }

  // Verify that the creator is still an admin.
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  const role = await dsSyncAction(folder);
  expect(role).toEqual('admin');

  // Perform key rotation.
  await cli.parseAsync(['ds', 'rotate-keys', folder], { from: 'user' });
  const role3 = await dsSyncAction(folder);
  expect(role3).toEqual('admin');

  // Sync all other clients. make all of them admins
  for (const client of others) {
    // Sync clients to check for member status.
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role = await dsSyncAction(folder);
    expect(role).toEqual('member');
    // Add clients as admins.
    await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
    await cli.parseAsync(['ds', 'add-admin', folder, client], { from: 'user' });
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role2 = await dsSyncAction(folder);
    expect(role2).toEqual('admin');
  }
  // Clean up.
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  for (const client of others) {
    await cli.parseAsync(['ds', 'remove-admin', folder, client], {
      from: 'user',
    });
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role = await dsSyncAction(folder);
    expect(role).toEqual('member');
    await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
    await cli.parseAsync(['ds', 'remove-member', folder, client], {
      from: 'user',
    });
  }
  // Process removals
  for (const client of others) {
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role = await dsSyncAction(folder);
    expect(role).toBeUndefined();
  }
});


it.skip('Cli-int-tests 4.', async () => {
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  const cli = await createCLI();
  // With 2 users it does work.
  const clients = [...Array(5).keys()].map(generateClientRandomIdentity);
  // It's reasonable that we do not do the following concurrently, as the client
  // will only do it once at a time when a user is using it.
  for (const client of clients) {
    await cli.parseAsync(['pki', 'create', client], { from: 'user' });
    await cli.parseAsync(['ds', 'register', client], { from: 'user' });
  }
  const current = await pkiCurrentAction();
  const creator1 = current[0];
  expect(creator1).toEqual(clients[clients.length - 1]);
  const others = clients.slice(0, clients.length - 1);
  expect(others).toHaveLength(clients.length - 1);
  // Create a folder where current is admin.
  const folder = (await dsCreateFolderAction()).toString();
  console.log('Folder created:', folder);
  // Share the folder with all other clients.
  for (const client of others) {
    await cli.parseAsync(['ds', 'share-folder', folder, client], {
      from: 'user',
    });
    await cli.parseAsync(['ds', 'upload', folder, FILE_PATH, FILENAME + client], {
      from: 'user',
    });
  }
  console.info('Folder shared with all clients and files uploaded.');
  // Verify that all clients see the folder.
  for (const client of clients) {
    console.log('Switching to client:', client);
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const folders = await dsListFoldersAction();
    expect(folders).toContain(Number(folder));
    expect(folders.length).toEqual(1);
  }
  const notVisibles: string[] = [];
  for (const other of others) {
    await cli.parseAsync(['pki', 'switch', other], { from: 'user' });
    for (const notVisible of notVisibles) {
      await cli.parseAsync(['ds', 'download', folder, notVisible, DOWNLOAD_PATH], {
        from: 'user',
      });
      const readPromise = fspromise.readFile(DOWNLOAD_PATH);
      await expect(readPromise).rejects.toThrow();
    }
    notVisibles.push(FILENAME + other);
    // Verify all the other ones are visible.
    await cli.parseAsync(['ds', 'download', folder, FILENAME + other, DOWNLOAD_PATH], {
      from: 'user',
    });
    const file3 = fs.readFileSync(DOWNLOAD_PATH);
    expect(file3).toStrictEqual(fs.readFileSync(FILE_PATH));
    fs.rmSync(DOWNLOAD_PATH);
  }
});

it.skip('Cli-int-tests.', async () => {
  pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
  dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
  const cli = await createCLI();
  // With 2 users it does work.
  const clients = [...Array(5).keys()].map(generateClientRandomIdentity);
  // It's reasonable that we do not do the following concurrently, as the client
  // will only do it once at a time when a user is using it.
  for (const client of clients) {
    await cli.parseAsync(['pki', 'create', client], { from: 'user' });
    await cli.parseAsync(['ds', 'register', client], { from: 'user' });
  }
  const current = await pkiCurrentAction();
  const creator1 = current[0];
  expect(creator1).toEqual(clients[clients.length - 1]);
  const others = clients.slice(0, clients.length - 1);
  expect(others).toHaveLength(clients.length - 1);
  // Create a folder where current is admin.
  const folder = (await dsCreateFolderAction()).toString();
  console.log('Folder created:', folder);
  // Share the folder with all other clients.
  for (const client of others) {
    await cli.parseAsync(['ds', 'share-folder', folder, client], {
      from: 'user',
    });
  }
  console.info('Folder shared with all clients.');
  // Verify that all clients see the folder.
  for (const client of clients) {
    console.log('Switching to client:', client);
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const folders = await dsListFoldersAction();
    expect(folders).toContain(Number(folder));
    expect(folders.length).toEqual(1);
  }
  console.info('All clients see the folder.');
  // Verify that all clients joined as members the folder.
  for (const client of others) {
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role = await dsSyncAction(folder);
    expect(role).toEqual('member');
  }
  // Verify that the creator is still an admin.
  await dsShareFolderAction(folder, creator1);
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  const role = await dsSyncAction(folder);
  expect(role).toEqual('admin');
  // Upload a file to the folder.
  await cli.parseAsync(['ds', 'upload', folder, FILE_PATH, FILENAME], {
    from: 'user',
  });
  // Download the file from the folder.
  await cli.parseAsync(['ds', 'download', folder, FILENAME, DOWNLOAD_PATH], {
    from: 'user',
  });
  // Verify that the file is the same.
  const file1 = fs.readFileSync(FILE_PATH);
  const file2 = fs.readFileSync(DOWNLOAD_PATH);
  fs.rmSync(DOWNLOAD_PATH);
  expect(file1).toStrictEqual(file2);
  expect(file1.length).toEqual(file2.length);
  // Verify that the other members also can see it.
  for (const client of others) {
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    await cli.parseAsync(['ds', 'download', folder, FILENAME, DOWNLOAD_PATH], {
      from: 'user',
    });
    const file3 = fs.readFileSync(DOWNLOAD_PATH);
    fs.rmSync(DOWNLOAD_PATH);
    expect(file1).toStrictEqual(file3);
    expect(file1.length).toEqual(file3.length);
  }
  // Add a member as admin, then remove it.
  const additionalMember = generateClientRandomIdentity();
  await cli.parseAsync(['pki', 'create', additionalMember], { from: 'user' });
  await cli.parseAsync(['ds', 'register', additionalMember], { from: 'user' });
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  await cli.parseAsync(['ds', 'share-folder', folder, additionalMember], {
    from: 'user',
  });
  await cli.parseAsync(['ds', 'add-admin', folder, additionalMember], {
    from: 'user',
  });
  // Verify that the member is an admin.
  await cli.parseAsync(['pki', 'switch', additionalMember], { from: 'user' });
  const role1 = await dsSyncAction(folder);
  expect(role1).toEqual('admin');
  // Now remove the admin privileges.
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  await cli.parseAsync(['ds', 'remove-admin', folder, additionalMember], {
    from: 'user',
  });
  // Verify that the member is still a member but not an admin.
  await cli.parseAsync(['pki', 'switch', additionalMember], { from: 'user' });
  const role2 = await dsSyncAction(folder);
  expect(role2).toEqual('member');
  // Remove the additionalMember.
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  await cli.parseAsync(['ds', 'remove-member', folder, additionalMember], {
    from: 'user',
  });
  // Verify that the member is no longer a member.
  await cli.parseAsync(['pki', 'switch', additionalMember], { from: 'user' });
  const _role = await dsSyncAction(folder);
  expect(_role).toBeUndefined();
  // Add all other members as admins.
  for (const client of others) {
    await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
    await cli.parseAsync(['ds', 'add-admin', folder, client], { from: 'user' });
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role = await dsSyncAction(folder);
    expect(role).toEqual('admin');
    console.log(`Client ${client} is now: ${role}`);
  }
  console.warn('All other members are now admins.');
  // Verify that the creator is still an admin.
  await cli.parseAsync(['pki', 'switch', creator1], { from: 'user' });
  const role3 = await dsSyncAction(folder);
  expect(role3).toEqual('admin');
  // Perform key rotation.
  await cli.parseAsync(['ds', 'rotate-keys', folder], { from: 'user' });
  const role4 = await dsSyncAction(folder);
  expect(role4).toEqual('admin');
  // Now remove all of them apart from one (including the creator).
  await cli.parseAsync(['pki', 'switch', additionalMember], { from: 'user' });
  const newOwner = others[0];
  const others2 = [creator1, ...others.slice(1)];
  await cli.parseAsync(['pki', 'switch', newOwner], { from: 'user' });
  await dsSyncAction(folder);
  for (const client of others2) {
    await cli.parseAsync(['ds', 'remove-admin', folder, client], {
      from: 'user',
    });
    await cli.parseAsync(['ds', 'remove-member', folder, client], {
      from: 'user',
    });
    await cli.parseAsync(['ds', 'rotate-keys', creator1], { from: 'user' });
  }
  console.warn('All other members are now removed.');
  // Sync other clients
  for (const client of others2) {
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    const role = await dsSyncAction(folder);
    // Verify the users were removed.
    expect(role).toBeUndefined();
    const folders = await dsListFoldersAction();
    expect(folders).toHaveLength(0);
  }
  // Now try to re-add them, one by one, and upload a file before each of them is added.
  await cli.parseAsync(['pki', 'switch', newOwner], { from: 'user' });
  const files = others2.map((client) => client + FILENAME);
  for (const client of others2) {
    await cli.parseAsync(
      ['ds', 'upload', folder, FILE_PATH, client + FILENAME],
      { from: 'user' }
    );
    await cli.parseAsync(['ds', 'share-folder', folder, client], {
      from: 'user',
    });
    await cli.parseAsync(['ds', 'add-admin', folder, client], { from: 'user' });
  }
  // Verify that all clients see the folder, and that they have access to the files after their addition.
  for (const client of others2) {
    await cli.parseAsync(['pki', 'switch', client], { from: 'user' });
    await dsSyncAction(folder);
    const folders = await dsListFoldersAction();
    expect(folders).toContain(Number(folder));
    expect(folders.length).toEqual(1);
    const role = await dsSyncAction(folder);
    expect(role).toEqual('member');
    const index = files.indexOf(client + FILENAME) + 1;
    expect(index).toEqual(others2.indexOf(client) + 1);
    const notVisibles = files.slice(0, );
    const visible = files.slice(files.indexOf(client + FILENAME) + 1);
    for (const file of visible) {
      await cli.parseAsync(['ds', 'download', folder, file, DOWNLOAD_PATH], {
        from: 'user',
      });
      const file3 = fs.readFileSync(DOWNLOAD_PATH);
      fs.rmSync(DOWNLOAD_PATH);
      expect(file1).toStrictEqual(file3);
      expect(file1.length).toEqual(file3.length);
    }
    for (const file of notVisibles) {
      await cli.parseAsync(['ds', 'download', folder, file, DOWNLOAD_PATH], {
        from: 'user',
      });
      const readPromise = fspromise.readFile(DOWNLOAD_PATH);
      await expect(readPromise).rejects.toThrow();
    }
  }
  // Clean up.
  for (const client of others2) {
    await cli.parseAsync(['pki', 'switch', newOwner], { from: 'user' });
    await cli.parseAsync(['ds', 'remove-admin', folder, client], {
      from: 'user',
    });
    await cli.parseAsync(['ds', 'remove-member', folder, client], {
      from: 'user',
    });
  }
});


