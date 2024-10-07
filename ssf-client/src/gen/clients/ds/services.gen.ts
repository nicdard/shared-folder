// This file is auto-generated by @hey-api/openapi-ts

import type { CancelablePromise } from './core/CancelablePromise';
import { OpenAPI } from './core/OpenAPI';
import { request as __request } from './core/request';
import type { $OpenApiTs } from './types.gen';

export class CrateService {
  /**
   * Return JSON version of an OpenAPI schema
   * @returns unknown Openapi spec of this server
   * @throws ApiError
   */
  public static openapi(): CancelablePromise<
    $OpenApiTs['/api-doc.json']['get']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/api-doc.json',
    });
  }

  /**
   * List all the folders in which the user participates.
   * @returns ListFolderResponse List of folders.
   * @throws ApiError
   */
  public static listFoldersForUser(): CancelablePromise<
    $OpenApiTs['/folders']['get']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/folders',
      errors: {
        401: 'Unkwown or unauthorized user.',
        500: "Internal Server Error, couldn't retrieve the users",
      },
    });
  }

  /**
   * Create a new folder and link it to the user.
   * @param data The data for the request.
   * @param data.formData
   * @returns FolderResponse New folder created.
   * @throws ApiError
   */
  public static createFolder(
    data: $OpenApiTs['/folders']['post']['req']
  ): CancelablePromise<$OpenApiTs['/folders']['post']['res'][201]> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/folders',
      formData: data.formData,
      mediaType: 'multipart/form-data',
      errors: {
        401: 'Unkwown or unauthorized user.',
        500: 'Internal Server Error',
      },
    });
  }

  /**
   * List all the users.
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @returns FolderResponse The requested folder.
   * @throws ApiError
   */
  public static getFolder(
    data: $OpenApiTs['/folders/{folder_id}']['get']['req']
  ): CancelablePromise<$OpenApiTs['/folders/{folder_id}']['get']['res'][200]> {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/folders/{folder_id}',
      path: {
        folder_id: data.folderId,
      },
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'Folder not found.',
        500: "Internal Server Error, couldn't retrieve the users",
      },
    });
  }

  /**
   * Unshare a folder with other users.
   * @param data The data for the request.
   * @param data.folderId The folder id.
   * @returns unknown User removed from folder.
   * @throws ApiError
   */
  public static removeSelfFromFolder(
    data: $OpenApiTs['/folders/{folder_id}']['delete']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}']['delete']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'DELETE',
      url: '/folders/{folder_id}',
      path: {
        folder_id: data.folderId,
      },
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'Not found.',
        500: "Internal Server Error, couldn't retrieve the users",
      },
    });
  }

  /**
   * Share a folder with other users.
   * If some of the users already can see the folder, they will be ignored.
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @param data.requestBody
   * @returns unknown Folder shared.
   * @throws ApiError
   */
  public static shareFolder(
    data: $OpenApiTs['/folders/{folder_id}']['patch']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}']['patch']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'PATCH',
      url: '/folders/{folder_id}',
      path: {
        folder_id: data.folderId,
      },
      body: data.requestBody,
      mediaType: 'application/json',
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'Not found.',
        500: "Internal Server Error, couldn't retrieve the users",
      },
    });
  }

  /**
   * Get a file from the cloud storage.
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @param data.fileId File identifier.
   * @returns FolderFileResponse The requested file.
   * @throws ApiError
   */
  public static getFile(
    data: $OpenApiTs['/folders/{folder_id}/files/{file_id}']['get']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/files/{file_id}']['get']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/folders/{folder_id}/files/{file_id}',
      path: {
        folder_id: data.folderId,
        file_id: data.fileId,
      },
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'File not found.',
        500: "Internal Server Error, couldn't retrieve the file",
      },
    });
  }

  /**
   * Upload a file to the cloud storage.
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @param data.fileId File identifier.
   * @param data.formData
   * @returns unknown File uploaded.
   * @throws ApiError
   */
  public static uploadFile(
    data: $OpenApiTs['/folders/{folder_id}/files/{file_id}']['post']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/files/{file_id}']['post']['res'][201]
  > {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/folders/{folder_id}/files/{file_id}',
      path: {
        folder_id: data.folderId,
        file_id: data.fileId,
      },
      formData: data.formData,
      mediaType: 'multipart/form-data',
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'Folder not found.',
        500: "Internal Server Error, couldn't retrieve the file",
      },
    });
  }

  /**
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @param data.requestBody
   * @returns FetchKeyPackageResponse Retrieved a key package.
   * @throws ApiError
   */
  public static fetchKeyPackage(
    data: $OpenApiTs['/folders/{folder_id}/keys']['post']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/keys']['post']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/folders/{folder_id}/keys',
      path: {
        folder_id: data.folderId,
      },
      body: data.requestBody,
      mediaType: 'application/json',
      errors: {
        401: 'Unkwown or unauthorized user.',
        500: 'Internal Server Error',
      },
    });
  }

  /**
   * Get the metadata of a folder. The metadata contain the list of files and their metadata.
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @returns FolderFileResponse The requested folder's metadata.
   * @throws ApiError
   */
  public static getMetadata(
    data: $OpenApiTs['/folders/{folder_id}/metadatas']['get']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/metadatas']['get']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/folders/{folder_id}/metadatas',
      path: {
        folder_id: data.folderId,
      },
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'File not found.',
        500: "Internal Server Error, couldn't retrieve the file",
      },
    });
  }

  /**
   * Upload a new version of the metadata of a folder. The metadata contain the list of files and their metadata.
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @param data.formData
   * @returns unknown Metadata file uploaded.
   * @throws ApiError
   */
  public static postMetadata(
    data: $OpenApiTs['/folders/{folder_id}/metadatas']['post']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/metadatas']['post']['res'][201]
  > {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/folders/{folder_id}/metadatas',
      path: {
        folder_id: data.folderId,
      },
      formData: data.formData,
      mediaType: 'multipart/form-data',
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'Folder not found.',
        500: "Internal Server Error, couldn't retrieve the file",
      },
    });
  }

  /**
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @returns GroupMessage Retrieved the eldest proposal.
   * @throws ApiError
   */
  public static getPendingProposal(
    data: $OpenApiTs['/folders/{folder_id}/proposals']['get']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/proposals']['get']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/folders/{folder_id}/proposals',
      path: {
        folder_id: data.folderId,
      },
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'Not found.',
        500: 'Internal Server Error',
      },
    });
  }

  /**
   * @param data The data for the request.
   * @param data.folderId Folder id.
   * @param data.formData
   * @returns unknown Create a proposal.
   * @throws ApiError
   */
  public static tryPublishProposal(
    data: $OpenApiTs['/folders/{folder_id}/proposals']['post']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/proposals']['post']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/folders/{folder_id}/proposals',
      path: {
        folder_id: data.folderId,
      },
      formData: data.formData,
      mediaType: 'multipart/form-data',
      errors: {
        401: 'Unkwown or unauthorized user.',
        409: 'Conflict: the user state is outdated, please fetch the pending proposals first.',
        500: 'Internal Server Error',
      },
    });
  }

  /**
   * Delete a proposal message.
   * @param data The data for the request.
   * @param data.folderId The folder id.
   * @param data.messageId The message to delete.
   * @returns unknown Message removed from the queue.
   * @throws ApiError
   */
  public static ackMessage(
    data: $OpenApiTs['/folders/{folder_id}/proposals/{message_id}']['delete']['req']
  ): CancelablePromise<
    $OpenApiTs['/folders/{folder_id}/proposals/{message_id}']['delete']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'DELETE',
      url: '/folders/{folder_id}/proposals/{message_id}',
      path: {
        folder_id: data.folderId,
        message_id: data.messageId,
      },
      errors: {
        401: 'Unkwown or unauthorized user.',
        404: 'Not found.',
        500: "Internal Server Error, couldn't delete the message",
      },
    });
  }

  /**
   * List all the users.
   * @returns ListUsersResponse List of users using the SSF.
   * @throws ApiError
   */
  public static listUsers(): CancelablePromise<
    $OpenApiTs['/users']['get']['res'][200]
  > {
    return __request(OpenAPI, {
      method: 'GET',
      url: '/users',
      errors: {
        401: 'Unkwown or unauthorized user.',
        500: "Internal Server Error, couldn't retrieve the users",
      },
    });
  }

  /**
   * Create a new user checking that the client certificate contains the email that is used to create the account.
   * @param data The data for the request.
   * @param data.requestBody
   * @returns unknown New account created.
   * @throws ApiError
   */
  public static createUser(
    data: $OpenApiTs['/users']['post']['req']
  ): CancelablePromise<$OpenApiTs['/users']['post']['res'][201]> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/users',
      body: data.requestBody,
      mediaType: 'application/json',
      errors: {
        400: 'Bad request.',
        401: 'Unauthorized user, please, set a valid client credential.',
        409: 'Conflict.',
      },
    });
  }

  /**
   * @param data The data for the request.
   * @param data.formData
   * @returns unknown New key package created.
   * @throws ApiError
   */
  public static publishKeyPackage(
    data: $OpenApiTs['/users/keys']['post']['req']
  ): CancelablePromise<$OpenApiTs['/users/keys']['post']['res'][201]> {
    return __request(OpenAPI, {
      method: 'POST',
      url: '/users/keys',
      formData: data.formData,
      mediaType: 'multipart/form-data',
      errors: {
        401: 'Unkwown or unauthorized user.',
        500: 'Internal Server Error',
      },
    });
  }
}
