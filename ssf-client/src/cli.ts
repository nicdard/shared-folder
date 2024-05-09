import { Command } from '@commander-js/extra-typings';
import { createClientCertificate, downloadCACertificate, isValid } from './pki';
import fspromise from 'fs/promises';
import { CLIENT_CERT_PATH, CLIENT_KEY_PATH, CLIENTS_CERT_DIR, saveCaTLSCredentials } from './authentication';
import { createFolder, listFolders, listUsers, register, uploadFile } from './ds';
import path from 'path';
import { startCLIRepl } from './repl';

function getClientFolderNameFromEmail(email: string): string {
  return email.replace('\.', '_').replace('@', '_');
}

function getClientFolder(folderPath: string, email: string): string {
  return path.join(folderPath, getClientFolderNameFromEmail(email));
}

function getClientCertAndKeyPaths(folderPath: string, email: string) {
  return {
    clientDir: getClientFolder(folderPath, email),
    certPath: path.join(getClientFolder(folderPath, email), 'cert.pem'),
    keyPath: path.join(getClientFolder(folderPath, email), 'key.pem'),
  }
}

/**
 * Setup the CLI environment.
 */
async function setup() {
  try {
    console.log(`Clients storage at: ${CLIENTS_CERT_DIR}`);
    console.log(`CA certificate storage at: ${CLIENT_CERT_PATH}\n`);
    await fspromise.mkdir(CLIENTS_CERT_DIR);
  } catch (_) {}
}

/**
 * Create a new CLI interface that will be used to interact with the Secure Shared Folder System.
 * @param exitCallback the callback to set the exit behavior of the CLI. Leave it undefined to avoid exiting the node process.
 * @returns the CLI interface.
 */
export function createCLI(exitCallback?: (() => void)): Command {

  setup();

  const program = new Command();
  program
    .version('0.0.1')
    .description('A CLI interface for the Secure Shared Folder System.')
    // Avoid exiting from the node process and remove error message.
    .exitOverride(exitCallback);
  
  // Add the PKI commands.
  const pki = program.command('pki').exitOverride();

  // Obtain a new CA certificate.
  pki.command('ca-cert')
    .description('Re-Install the CA certificate from the CA server.')
    .action(async () => {
      try {
        const caCert = await downloadCACertificate();
        saveCaTLSCredentials(caCert);
        console.log('CA certificate saved successfully.');
      } catch (error) {
        console.error(`Couldn't download the CA certificate: ${error}`);
      }
    })
    .exitOverride(exitCallback);

  // Remote verify a certificate.
  pki.command('verify')
    .description('Verify a certificate using the CA server.')
    .option('-c --certificate <certificate>', 'The PEM-encoded certificate to verify.', null)
    .option('-f --file <path>', 'The relative path to the PEM-encoded certificate to verify.', null)
    .action(async ({ certificate, file }) => {
      try {
        if (certificate == null && file == null) {
          console.error('You must provide a certificate to verify.');
          return;
        }
        const toVerify = certificate ?? (await fspromise.readFile(path.join(process.cwd(), file))).toString();
        const valid = await isValid(toVerify);
        if (valid) {
          console.log('The certificate is valid.');
        } else {
          console.log('The certificate is invalid.');
        }
      } catch (error) {
        console.error(`Couldn't verify the certificate: ${error}`);
      }
    })
    .exitOverride(exitCallback);

  const createIdentity = async (email: string, { clientsDir, reThrow = false }: { clientsDir: string, reThrow?: boolean}) => {
    try {
      const [certificate, keyPair] = await createClientCertificate(email);
      const { certPath, keyPath, clientDir } = getClientCertAndKeyPaths(clientsDir, email);
      try {
        await fspromise.mkdir(clientDir);
        await fspromise.writeFile(certPath, certificate);
        await fspromise.writeFile(keyPath, keyPair);
      } catch (error) {
        console.error(`Error saving the client credentials to ${clientsDir}: ${error}.\nPlease take note of the private key:\n ${keyPair} and the certificate:\n ${certificate}`);
        if (reThrow) {
          throw error;
        }
      }
    } catch (error) {
      console.error(`Error creating the client certificate: ${error}.`);
      if (reThrow) {
        throw error;
      }
    }
  }

  pki.command('ca-cert')
    .description('Re-Install the CA certificate from the CA server.')

  // Obtain a new CA-signed certificate for a new client.
  pki.command('create')
    .description("Create a new PKI client certificate.")
    .argument('<email>', 'The email address to set in the certificate.')
    .option('-o, --clients-dir <dir>', 'The output dir to save the certificate and private key.', CLIENTS_CERT_DIR)
    .action(createIdentity)
    .exitOverride(exitCallback);

  const switchIdentity = async (email: string, { clientsDir }: { clientsDir: string }) => {
    const { certPath, keyPath } = getClientCertAndKeyPaths(clientsDir, email); 
    await fspromise.copyFile(certPath, CLIENT_CERT_PATH);
    await fspromise.copyFile(keyPath, CLIENT_KEY_PATH);
  }

  // Use the identity for the selected user profile (email) stored in the filesystem. This operation is STATEFUL.
  pki.command('switch')
    .description('Use one of the client private keys and certificates saved under ./clients (by default) folder as Client Certificate in mutual TLS authentication with the server. This is a stateful operation, subsequent commands will use this identity.')
    .argument('<email>', 'The email address contained in the certificate to use')
    .option('-d, --clients-dir <dir>', 'The directory containing the subfolder with the certificate and key for the given email.', CLIENTS_CERT_DIR)
    .action(async (email, { clientsDir }) => {
      try {
        await switchIdentity(email, { clientsDir });
      } catch (error) {
        console.error(`Error switching the client certificate using:\n${clientsDir}.\n${error}.\nNOTE: the state could have been left in an inconsistent status, remove the ${CLIENT_CERT_PATH} and ${CLIENT_KEY_PATH}.\nThen try to set a new identity again.`)
      }
    })
    .exitOverride(exitCallback);


  // Add DS commands.
  const ds = program.command('ds').exitOverride();

  // Register a new user on the SSF system.
  ds.command('register')
    .argument('<email>', 'The email address to register as a client of the SSF system. A cerficate should already exist.')
    .option('-d, --clients-dir <dir>', 'The directory containing the subfolder with the certificate and key for the given email.', CLIENTS_CERT_DIR)
    .option('-c, --create', 'A flag indicating that a client identity should be registered with the PKI if loading it fails.')
    .action(async (email, { clientsDir, create }) => {
      if (create) {
        try {
          await createIdentity(email, { clientsDir, reThrow: true });
        } catch (_) {
          console.error(`Couldn't register a new user for email: ${email}`)
        }
      }
      try {
        await switchIdentity(email, { clientsDir });
      } catch (error) {
        console.error(`Couldn't use the client identity associated with the user: ${email}, you can try re-run this command with the option '--create' to create an associated identity with the PKI.`);
      }
      try {
        await register(email);
      } catch (error) {
        console.error(`Error registering the user ${email}: ${error}`);
      }
    })
    .exitOverride(exitCallback);

  // List all users on the SSF system.
  ds.command('list-users').action(async () => {
    try {
      const users = await listUsers();
      console.log(users.map((user) => `- ${user}`).join("\n"))
    } catch (error) {
      console.error(`Couldn't list the users: ${error}`);
    }
  }).exitOverride();

  // Create a folder owned by the current user.
  ds.command('create-folder').action(async () => {
    try {
      const id = await createFolder();
      console.log(`Created folder with id: ${id}`);
    } catch (error) {
      console.error(`Couldn't create folder for the current user, please check the validity of the client identity: ${error}.`);
    }
  })
  .exitOverride(exitCallback);

  // List all folders where the current user is participating.
  ds.command('list-folders').action(async () => {
    try {
      const folders = await listFolders();
      console.log(folders.map(id => `- ${id}`).join('\n'));
    } catch (error) {
      console.error(`Couldn't retrieve the list of folders for the current user, please check the validity of the client identity: ${error}.`);
    }
  })
  .exitOverride(exitCallback);

  // Upload a file in a folder.
  ds.command('upload')
    .argument('<folder-id>', 'The folder id where to upload the file.')
    .argument('<file-path>', 'The file path to upload.')
    .action(async (folderId, filePath) => {
      try {
        const id = Number(folderId);
        await uploadFile(id, filePath);
      } catch (error) {
        console.error(`Couldn't upload the file to folder: ${error}`);
      }
    })
    .exitOverride(exitCallback);

  return program;
}
