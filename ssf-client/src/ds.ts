import { CrateService as dsclient } from './gen/clients/ds';
import { loadDsTLSInterceptor } from './authentication';
import { PathLike } from 'fs';

/**
 * @param email the email to register. This needs to match the one in the client certificate.
 * @see loadDsTLSInterceptor
 */
export async function register(email: string) {
    await dsclient.createUser({
        requestBody: {
            email
        }
    });
}

/**
 * @returns the users currently present on the system.
 */
export async function listUsers(): Promise<string[]> {
    return (await dsclient.listUsers()).emails;    
}

/**
 * @returns a new folder for the current user.
 */
export async function createFolder(): Promise<number> {
    return (await dsclient.createFolder()).id;
}

/**
 * @returns all folders where the current user is a participant.
 */
export async function listFolders(): Promise<number[]> {
    return (await dsclient.listFoldersForUser()).folders
        .map((folderResponse) => folderResponse.id);
}

/**
 * Uploads a file in the given folder.
 * @param folderId The folder where to upload the file.
 */
export async function uploadFile(folderId: number, file: PathLike) {
    const folderResponse = (await dsclient.getFolder({ folderId })).id;
    // const metadata = (await dsclient.getMetadata({ folderId }));
    // console.log(metadata);
    // await dsclient.uploadFile();
}