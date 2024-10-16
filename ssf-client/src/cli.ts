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
import {
  createClientCertificate,
  downloadCACertificate,
  getClientCertificate,
  isValid,
  localIsValid,
} from './pki';
import fspromise from 'fs/promises';
import {
  CA_CERT_PATH,
  CLIENT_CERT_PATH,
  CLIENT_KEY_PATH,
  CLIENTS_CERT_DIR,
  saveCaTLSCredentials,
} from './protocol/authentication';
import {
  createFolder,
  downloadFile,
  listAllFiles,
  listFolders,
  listUsers,
  register,
  shareFolder,
  uploadFile,
} from './ds';
import path from 'path';
import { parseEmailsFromCertificate } from 'common';
import { importECDHPublicKeyPEMFromCertificate } from './protocol/commonCrypto';
import { protocol, protocolClient } from './protocol/protocolCommon';

/**
 * @param email The email of the client.
 * @returns The folder name for the client where to store the certificate and private key.
 */
function getClientFolderNameFromEmail(email: string): string {
  return email.replace('.', '_').replace('@', '_');
}

/**
 * @param folderPath The path to the parent folder where to store the client certificates.
 * @param email The email of the client.
 * @returns The folder path for the client where to store the certificate and private key.
 */
export function getClientFolder(folderPath: string, email: string): string {
  return path.join(folderPath, getClientFolderNameFromEmail(email));
}

/**
 * @param folderPath The path to the parent folder where to store the client certificates.
 * @param email The email of the client.
 * @returns The certificate and private key full paths for the client, as well as the client folder where those are stored.
 */
function getClientCertAndKeyPaths(folderPath: string, email: string) {
  return {
    clientDir: getClientFolder(folderPath, email),
    certPath: path.join(getClientFolder(folderPath, email), 'cert.pem'),
    keyPath: path.join(getClientFolder(folderPath, email), 'key.pem'),
  };
}

/**
 * Setup the CLI environment.
 */
async function setup() {
  try {
    console.log(`Running with protocol: ${protocol}`);
    console.log(`Clients storage at: ${CLIENTS_CERT_DIR}`);
    console.log(`CA certificate storage at: ${CA_CERT_PATH}\n`);
    await fspromise.mkdir(CLIENTS_CERT_DIR);
  } catch (_) {
    // Ignore the error if the folder already exists.
  }
}

/**
 * Create a new CLI interface that will be used to interact with the Secure Shared Folder System.
 * @param exitCallback the callback to set the exit behavior of the CLI. Leave it undefined to avoid exiting the node process.
 * @returns the CLI interface.
 */
export async function createCLI(exitCallback?: () => void): Promise<Command> {
  await setup();

  const program = new Command();
  program
    .version('0.0.1')
    .description('A CLI interface for the Secure Shared Folder System.')
    // Avoid exiting from the node process and remove error message.
    .exitOverride(exitCallback);
  /**
  program
    .command('protocol')
    .description('Set the protocol for the folder operations, Baseline or GRaPPA')
    .argument('<protocol>', 'Either `baseline` or `GRaPPA`.')
    .action((protocol: Protocol) => {
      if (protocol != 'GRaPPA' && protocol != 'baseline') {
        throw new Error('Protocol must be either GRaPPA or baseline');
      }
      currentProtocol = protocol;
    })
    .exitOverride(exitCallback);
    */

  // Add the PKI commands.
  const pki = program.command('pki').exitOverride();

  // Obtain a new CA certificate.
  pki
    .command('ca-cert')
    .description('Re-Install the CA certificate from the CA server.')
    .action(pkiCaCertAction)
    .exitOverride(exitCallback);

  // Curried function to validate a certificate.
  const validateCertificate =
    (validator: (toValidate: string) => Promise<boolean>) =>
    async ({ certificate, file }: { certificate?: string; file?: string }) => {
      try {
        if (certificate == null && file == null) {
          console.error('You must provide a certificate to verify.');
          return;
        }
        const toVerify =
          certificate ??
          (await fspromise.readFile(path.join(process.cwd(), file))).toString();
        const valid = await validator(toVerify);
        if (valid) {
          console.log('The certificate is valid.');
        } else {
          console.log('The certificate is invalid.');
        }
      } catch (error) {
        console.error(`Couldn't verify the certificate.`, error);
      }
    };

  // Remote verify a certificate.
  pki
    .command('verify')
    .description('Verify a certificate using the CA server.')
    .option(
      '-c --certificate <certificate>',
      'The PEM-encoded certificate to verify.',
      null
    )
    .option(
      '-f --file <path>',
      'The relative path to the PEM-encoded certificate to verify.',
      null
    )
    .action(validateCertificate(isValid))
    .exitOverride(exitCallback);

  // Local verify a certificate.
  pki
    .command('verify-local')
    .description(
      'Verify a certificate using the CA certificate stored locally.'
    )
    .option(
      '-c --certificate <certificate>',
      'The PEM-encoded certificate to verify.',
      null
    )
    .option(
      '-f --file <path>',
      'The relative path to the PEM-encoded certificate to verify.',
      null
    )
    .action(
      validateCertificate((certificate: string) =>
        Promise.resolve(localIsValid(certificate))
      )
    )
    .exitOverride(exitCallback);

  // Obtain a new CA-signed certificate for a new client.
  pki
    .command('create')
    .description('Create a new PKI client certificate.')
    .argument('<email>', 'The email address to set in the certificate.')
    .option(
      '-o, --clients-dir <dir>',
      'The output dir to save the certificate and private key.',
      CLIENTS_CERT_DIR
    )
    .action(pkiCreateIdentityAction)
    .exitOverride(exitCallback);

  // Get the client certificate for a given user email.
  pki
    .command('get')
    .description('Get the client certificate for a given user email.')
    .argument('<email>', 'The email address to get the certificate for.')
    .action(async (email) => {
      try {
        const certificate = await getClientCertificate(email);
        console.log(certificate);
      } catch (error) {
        console.error(`Couldn't get the client certificate.`, error);
      }
    })
    .exitOverride(exitCallback);

  // Use the identity for the selected user profile (email) stored in the filesystem. This operation is STATEFUL.
  pki
    .command('switch')
    .description(
      'Use one of the client private keys and certificates saved under ./clients (by default) folder as Client Certificate in mutual TLS authentication with the server. This is a stateful operation, subsequent commands will use this identity.'
    )
    .argument(
      '<email>',
      'The email address contained in the certificate to use'
    )
    .option(
      '-d, --clients-dir <dir>',
      'The directory containing the subfolder with the certificate and key for the given email.',
      CLIENTS_CERT_DIR
    )
    .action(pkiSwitchAction)
    .exitOverride(exitCallback);

  // Display the emails of the current selected client identity.
  pki
    .command('current')
    .description('Display the email of the current selected client identity.')
    .action(invokeAsVoid(pkiCurrentAction))
    .exitOverride(exitCallback);

  // Add DS commands.
  const ds = program.command('ds').exitOverride();

  // Register a new user on the SSF system.
  ds.command('register')
    .argument(
      '<email>',
      'The email address to register as a client of the SSF system. A cerficate should already exist.'
    )
    .option(
      '-d, --clients-dir <dir>',
      'The directory containing the subfolder with the certificate and key for the given email.',
      CLIENTS_CERT_DIR
    )
    .option(
      '-c, --create',
      'A flag indicating that a client identity should be registered with the PKI if loading it fails.'
    )
    .action(dsRegisterAction)
    .exitOverride(exitCallback);

  // List all users on the SSF system.
  ds.command('list-users')
    .action(async () => {
      try {
        const users = await listUsers();
        console.log(users.map((user) => `- ${user}`).join('\n'));
      } catch (error) {
        console.error(`Couldn't list the users.`, error);
      }
    })
    .exitOverride();

  // Create a folder owned by the current user.
  ds.command('create-folder')
    .action(invokeAsVoid(dsCreateFolderAction))
    .exitOverride(exitCallback);

  // List all folders where the current user is participating.
  ds.command('list-folders')
    .action(invokeAsVoid(dsListFoldersAction))
    .exitOverride(exitCallback);

  // Share a folder with a user.
  // TODO: should we also get the version as parameter?
  ds.command('share-folder')
    .argument('<folder-id>', 'The folder id to share.')
    .argument('<other>', 'The email of the user to share the folder with.')
    .action(dsShareFolderAction);

  // Upload a file in a folder.
  ds.command('upload')
    .argument('<folder-id>', 'The folder id where to upload the file.')
    .argument('<file-path>', 'The file path to upload.')
    .argument('<file-name>', 'The file name to save (hidden from the server).')
    .action(async (folderId, filePath, fileName) => {
      try {
        const { emails, cert } = await getCurrentUserIdentity();
        if (emails.length != 1) {
          throw new Error(
            'The current client identity should have only one email associated with it.'
          );
        }
        const senderSkPEM = await fspromise.readFile(CLIENT_KEY_PATH);
        const id = Number(folderId);
        const fileId = await uploadFile(
          id,
          emails[0],
          senderSkPEM.toString(),
          cert,
          fileName,
          filePath
        );
        console.log(`The id visible to the server for this file is ${fileId}`);
        await syncNotifications(emails[0]);
        /*const filesJSON: FileJson = JSON.parse(
          await fspromise.readFile(FILES_JSON, 'utf-8').catch((e) => '{}')
        ) as FileJson;
        filesJSON[fileName] = fileId;
        await fspromise.writeFile(FILES_JSON, JSON.stringify(filesJSON));
        */
      } catch (error) {
        console.error(`Couldn't upload the file to folder.`, error);
      }
    })
    .exitOverride(exitCallback);

  // Download a file from a folder.
  ds.command('download')
    .argument('<folder-id>', 'The folder id where to download the file.')
    .argument('<file-name>', 'The name of the file to download.')
    .argument(
      '<dest>',
      'The name of the file where to save the downloaded content.'
    )
    .action(async (folderId, fileName, dest) => {
      try {
        const { emails, cert } = await getCurrentUserIdentity();
        if (emails.length != 1) {
          throw new Error(
            'The current client identity should have only one email associated with it.'
          );
        }
        const senderSkPEM = await fspromise.readFile(CLIENT_KEY_PATH);
        const folder = Number(folderId);
        /*const filesJSON: FileJson = JSON.parse(
          await fspromise.readFile(FILES_JSON, 'utf-8')
        ) as FileJson;
        const fileId = filesJSON[fileName];*/
        const mappings = await listAllFiles(
          folder,
          emails[0],
          senderSkPEM.toString(),
          cert
        );
        const fileContent = await downloadFile(
          folder,
          emails[0],
          senderSkPEM.toString(),
          cert,
          mappings[fileName]
        );
        await fspromise.writeFile(dest, new Uint8Array(fileContent));
        await syncNotifications(emails[0]);
      } catch (error) {
        console.error(`Couldn't download the file from folder.`, error);
      }
    });

  // List all of the files in the folder (like `ls`)
  ds.command('list-files')
    .argument('<folder-id>', 'The folder id from where to list files')
    .action(async (folderId) => {
      try {
        const { emails, cert } = await getCurrentUserIdentity();
        if (emails.length != 1) {
          throw new Error(
            'The current client identity should have only one email associated with it.'
          );
        }
        const skPEM = await fspromise.readFile(CLIENT_KEY_PATH);
        const mappings = await listAllFiles(
          Number(folderId),
          emails[0],
          skPEM.toString(),
          cert
        );
        const fileNameList = Object.keys(mappings)
          .sort()
          .map((fileName) => ` - ${fileName}`)
          .join('\n');
        console.log(fileNameList);
        await syncNotifications(emails[0]);
      } catch (error) {
        console.error(`Couldn't list files from folder.`, error);
      }
    });

  ds.command('sync').argument('<folder-id>').action(invokeAsVoid(dsSyncAction));

  ds.command('add-admin')
    .argument('<folder-id>')
    .argument('<email>')
    .action(async (folderId, email) => {
      try {
        const { emails, cert } = await getCurrentUserIdentity();
        if (emails.length != 1) {
          throw new Error(
            'The current client identity should have only one email associated with it.'
          );
        }
        await protocolClient.addAdmin(emails[0], folderId, email);
      } catch (error) {
        console.error(`Couldn't add admin to folder ${folderId}: `, error);
      }
    });

  ds.command('remove-admin')
    .argument('<folder-id>')
    .argument('<email>')
    .action(async (folderId, email) => {
      try {
        const { emails, cert } = await getCurrentUserIdentity();
        if (emails.length != 1) {
          throw new Error(
            'The current client identity should have only one email associated with it.'
          );
        }
        await protocolClient.removeAdmin(emails[0], folderId, email);
        await syncNotifications(emails[0]);
      } catch (error) {
        console.error(`Couldn't remove admin from folder ${folderId}: `, error);
      }
    });

  ds.command('remove-member')
    .argument('<folder-id>')
    .argument('<email>')
    .action(async (folderId, email) => {
      try {
        const { emails, cert } = await getCurrentUserIdentity();
        if (emails.length != 1) {
          throw new Error(
            'The current client identity should have only one email associated with it.'
          );
        }
        await protocolClient.removeMember(emails[0], folderId, email);
        await syncNotifications(emails[0]);
      } catch (error) {
        console.error(
          `Couldn't remove member from folder ${folderId}: `,
          error
        );
      }
    });

  ds.command('rotate-keys')
    .argument('<folder-id>')
    .action(async (folderId) => {
      try {
        const { emails, cert } = await getCurrentUserIdentity();
        if (emails.length != 1) {
          throw new Error(
            'The current client identity should have only one email associated with it.'
          );
        }
        await protocolClient.rotateKeys(emails[0], folderId);
        await syncNotifications(emails[0]);
      } catch (error) {
        console.error(`Couldn't rotate keys for folder ${folderId}: `, error);
      }
    });

  return program;
}

// Visible for testing.
export const pkiCreateIdentityAction = async (
  email: string,
  { clientsDir, reThrow = false }: { clientsDir: string; reThrow?: boolean }
) => {
  try {
    const [certificate, keyPair] = await createClientCertificate(email);
    const { certPath, keyPath, clientDir } = getClientCertAndKeyPaths(
      clientsDir,
      email
    );
    try {
      await fspromise.mkdir(clientDir);
      await fspromise.writeFile(certPath, certificate);
      await fspromise.writeFile(keyPath, keyPair);
    } catch (error) {
      console.error(
        `Error saving the client credentials to ${clientsDir}.\nPlease take note of the private key:\n ${keyPair} and the certificate:\n ${certificate}`,
        error
      );
      if (reThrow) {
        throw error;
      }
    }
  } catch (error) {
    console.error(`Error creating the client certificate.`, error);
    if (reThrow) {
      throw error;
    }
  }
};

export const dsShareFolderAction = async (folderId: string, other: string) => {
  try {
    const { emails, cert } = await getCurrentUserIdentity();
    if (emails.length != 1) {
      throw new Error(
        'The current client identity should have only one email associated with it.'
      );
    }
    const senderSkPEM = await fspromise.readFile(CLIENT_KEY_PATH);
    const id = Number(folderId);
    await shareFolder(id, emails[0], senderSkPEM.toString(), cert, other);
    await syncNotifications(emails[0]);
  } catch (error) {
    console.error(
      `Couldn't share the folder ${folderId} with ${other}: `,
      error
    );
  }
};

export const dsSyncAction = async (folderId: string) => {
  try {
    const { emails, cert } = await getCurrentUserIdentity();
    if (emails.length != 1) {
      throw new Error(
        'The current client identity should have only one email associated with it.'
      );
    }
    if (protocol === 'GRaPPA') {
      return await protocolClient.syncFolder(emails[0], folderId);
    }
  } catch (error) {
    console.error(`Couldn't sync folder ${folderId}: `, error);
  }
};

export const dsCreateFolderAction = async () => {
  try {
    const { emails, cert } = await getCurrentUserIdentity();
    if (emails.length != 1) {
      throw new Error(
        'The current client identity should have only one email associated with it.'
      );
    }
    const senderPkPEM = await importECDHPublicKeyPEMFromCertificate(cert);
    const { id, etag } = await createFolder({
      senderIdentity: emails[0],
      senderPkPEM,
    });
    if (etag == null) {
      throw new Error("Invalid etag, couldn't create the folder.");
    }
    console.log(
      `Created folder with id: ${id}. The folder version is: ${etag}`
    );
    return Promise.resolve(id);
  } catch (error) {
    console.error(
      `Couldn't create folder for the current user, please check the validity of the client identity.`,
      error
    );
  }
};

export const dsListFoldersAction = async () => {
  try {
    const { emails, cert } = await getCurrentUserIdentity();
    if (emails.length != 1) {
      throw new Error(
        'The current client identity should have only one email associated with it.'
      );
    }
    const folders = await listFolders();
    console.log(folders.map((id) => `- ${id}`).join('\n'));
    await syncNotifications(emails[0]);
    return Promise.resolve(folders);
  } catch (error) {
    console.error(
      `Couldn't retrieve the list of folders for the current user, please check the validity of the client identity.`,
      error
    );
  }
};

export const dsRegisterAction = async (
  email: string,
  { clientsDir, create }: { clientsDir?: string; create?: boolean }
) => {
  if (create) {
    try {
      await pkiCreateIdentityAction(email, { clientsDir, reThrow: true });
    } catch (_) {
      console.error(`Couldn't register a new user for email: ${email}`);
    }
  }
  try {
    await switchIdentity(email, { clientsDir });
  } catch (error) {
    console.error(
      `Couldn't use the client identity associated with the user: ${email}, you can try re-run this command with the option '--create' to create an associated identity with the PKI.`
    );
  }
  try {
    await register(email);
    await protocolClient.register(email);
  } catch (error) {
    console.error(`Error registering the user ${email}.`, error);
  }
};

export const pkiCurrentAction = async () => {
  try {
    const { emails } = await getCurrentUserIdentity();
    console.log(
      'Here the emails associated with the current client identity: '
    );
    console.log(emails.map((e) => `- ${e}`).join('\n'));
    return Promise.resolve(emails);
  } catch (error) {
    console.error(
      "Couldn't retrieve the emails associated with the current client identity.",
      error
    );
  }
};

export const pkiCaCertAction = async () => {
  try {
    const caCert = await downloadCACertificate();
    saveCaTLSCredentials(caCert);
    console.log('CA certificate saved successfully.');
  } catch (error) {
    console.error(`Couldn't download the CA certificate.`, error);
  }
};

export const pkiSwitchAction = async (
  email: string,
  { clientsDir }: { clientsDir: string }
) => {
  try {
    await switchIdentity(email, { clientsDir });
    await protocolClient.load(email);
    await syncNotifications(email);
  } catch (error) {
    console.error(
      `Error switching the client certificate using:\n${clientsDir}.\n.\nNOTE: the state could have been left in an inconsistent status, remove the ${CLIENT_CERT_PATH} and ${CLIENT_KEY_PATH}.\nThen try to set a new identity again.`,
      error
    );
  }
};

export const switchIdentity = async (
  email: string,
  { clientsDir }: { clientsDir: string }
) => {
  const { certPath, keyPath } = getClientCertAndKeyPaths(clientsDir, email);
  await fspromise.copyFile(certPath, CLIENT_CERT_PATH);
  await fspromise.copyFile(keyPath, CLIENT_KEY_PATH);
};

export const syncNotifications = async (email: string) => {
  const { folders, keyPackages } = protocolClient.getFoldersToSync();
  const p1 = Promise.all(
    folders.map(async (folderId) => {
      await protocolClient.syncFolder(email, folderId.toString());
    })
  );
  return p1;
  // When joining a group a new key package is sent to the server.
  /*
  const p2 = Promise.all(Array.from({ length: keyPackages })
    .map(async () => {
      await mlsGenerateKeyPackage(string2Uint8Array(email));
    }));
  return Promise.all([p1, p2]);
  */
};

const getCurrentUserIdentity = async () => {
  const currentClientCertificate = await fspromise.readFile(CLIENT_CERT_PATH);
  const cert = currentClientCertificate.toString();
  const emails: string[] = parseEmailsFromCertificate(cert);
  return { emails, cert };
};

function invokeAsVoid(fn: (...args: unknown[]) => Promise<unknown>) {
  return async (...args: unknown[]) => {
    await fn(...args);
  };
}
