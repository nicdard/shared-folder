// This file is auto-generated by @hey-api/openapi-ts

/**
 * Patch a proposal, publishing an application message.
 */
export type ApplicationMessageRequest = {
  /**
   * The message ids to which the application message is related.
   */
  message_ids: Array<number>;
  /**
   * The proposal to upload.
   */
  payload: Blob | File;
};

/**
 * Create the folder with the initial Metadata file.
 */
export type CreateFolderRequest = {
  /**
   * The metadata file to upload.
   */
  metadata: Blob | File;
};

/**
 * Create a key package for a user.
 */
export type CreateKeyPackageRequest = {
  /**
   * The metadata file to upload.
   */
  key_package: Blob | File;
};

export type CreateKeyPackageResponse = {
  /**
   * The id of the created key package.
   */
  key_package_id: number;
};

export type CreateUserRequest = {
  /**
   * The email contained in the associated credentials sent through mTLS.
   */
  email: string;
};

/**
 * Retrieves a key package of another user.
 */
export type FetchKeyPackageRequest = {
  /**
   * The user email
   */
  user_email: string;
};

/**
 * Upload a file to the server.
 */
export type FetchKeyPackageResponse = {
  /**
   * The payload.
   */
  payload: Blob | File;
};

export type FolderFileResponse = {
  etag?: string | null;
  file: Blob | File;
  version?: string | null;
};

export type FolderResponse = {
  etag?: string | null;
  /**
   * The id of the folder.
   */
  id: number;
  metadata_content?: (Blob | File) | null;
  version?: string | null;
};

export type GroupMessage = {
  /**
   * The application that should handle the message.
   */
  application_payload: Blob | File;
  /**
   * The folder id.
   */
  folder_id: number;
  /**
   * The folder the group is sharing.
   */
  message_id: number;
  /**
   * The payload of the GRaPPA message.
   */
  payload: Blob | File;
};

export type ListFolderResponse = {
  folders: Array<number>;
};

export type ListUsersResponse = {
  /**
   * The emails of the users.
   */
  emails: Array<string>;
};

export type MetadataUpload = {
  /**
   * The metadata file to upload.
   */
  metadata: Blob | File;
  /**
   * The previous metadata etag to which this file is related.
   */
  parent_etag?: string | null;
  /**
   * The previous metadata version to which this file is related.
   */
  parent_version?: string | null;
};

/**
 * Create a proposal.
 */
export type ProposalMessageRequest = {
  /**
   * The proposal to upload.
   */
  proposal: Blob | File;
};

export type ProposalResponse = {
  message_ids: Array<number>;
};

export type ShareFolderRequest = {
  /**
   * The emails of the users to share the folder with. The id is extracted from the path.
   */
  emails: Array<string>;
};

export type ShareFolderRequestWithProposal = {
  /**
   * The user to share the folder with.
   */
  email: string;
  /**
   * The proposal to upload.
   */
  proposal: Blob | File;
};

/**
 * Upload a file to the server.
 */
export type Upload = {
  /**
   * The file to upload.
   */
  file: Blob | File;
  /**
   * The metadata file to upload.
   */
  metadata: Blob | File;
  /**
   * The previous metadata etag to which this file is related.
   */
  parent_etag?: string | null;
  /**
   * The previous metadata version to which this file is related.
   */
  parent_version?: string | null;
};

/**
 * When a file is uploaded successfully, an etag is returned with the latest version of the metadata file of the folder.
 */
export type UploadFileResponse = {
  /**
   * The metadata etag.
   */
  etag?: string | null;
  /**
   * The metadata version.
   */
  version?: string | null;
};

export type $OpenApiTs = {
  '/api-doc.json': {
    get: {
      res: {
        /**
         * Openapi spec of this server
         */
        200: unknown;
      };
    };
  };
  '/folders': {
    get: {
      res: {
        /**
         * List of folders.
         */
        200: ListFolderResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Internal Server Error, couldn't retrieve the users
         */
        500: unknown;
      };
    };
    post: {
      req: {
        formData: CreateFolderRequest;
      };
      res: {
        /**
         * New folder created.
         */
        201: FolderResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Internal Server Error
         */
        500: unknown;
      };
    };
  };
  '/folders/{folder_id}': {
    get: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
      };
      res: {
        /**
         * The requested folder.
         */
        200: FolderResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Folder not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't retrieve the users
         */
        500: unknown;
      };
    };
    delete: {
      req: {
        /**
         * The folder id.
         */
        folderId: number;
      };
      res: {
        /**
         * User removed from folder.
         */
        200: unknown;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't retrieve the users
         */
        500: unknown;
      };
    };
    patch: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
        requestBody: ShareFolderRequest;
      };
      res: {
        /**
         * Folder shared.
         */
        200: unknown;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't retrieve the users
         */
        500: unknown;
      };
    };
  };
  '/folders/{folder_id}/files/{file_id}': {
    get: {
      req: {
        /**
         * File identifier.
         */
        fileId: string;
        /**
         * Folder id.
         */
        folderId: number;
      };
      res: {
        /**
         * The requested file.
         */
        200: FolderFileResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * File not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't retrieve the file
         */
        500: unknown;
      };
    };
    post: {
      req: {
        /**
         * File identifier.
         */
        fileId: string;
        /**
         * Folder id.
         */
        folderId: number;
        formData: Upload;
      };
      res: {
        /**
         * File uploaded.
         */
        201: unknown;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Folder not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't retrieve the file
         */
        500: unknown;
      };
    };
  };
  '/folders/{folder_id}/keys': {
    post: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
        requestBody: FetchKeyPackageRequest;
      };
      res: {
        /**
         * Retrieved a key package.
         */
        200: FetchKeyPackageResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Internal Server Error
         */
        500: unknown;
      };
    };
  };
  '/folders/{folder_id}/metadatas': {
    get: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
      };
      res: {
        /**
         * The requested folder's metadata.
         */
        200: FolderFileResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * File not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't retrieve the file
         */
        500: unknown;
      };
    };
    post: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
        formData: MetadataUpload;
      };
      res: {
        /**
         * Metadata file uploaded.
         */
        201: unknown;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Folder not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't retrieve the file
         */
        500: unknown;
      };
    };
  };
  '/folders/{folder_id}/proposals': {
    get: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
      };
      res: {
        /**
         * Retrieved the eldest proposal.
         */
        200: GroupMessage;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Not found.
         */
        404: unknown;
        /**
         * Too many requests.
         */
        429: unknown;
        /**
         * Internal Server Error
         */
        500: unknown;
      };
    };
    post: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
        formData: ProposalMessageRequest;
      };
      res: {
        /**
         * Create a proposal.
         */
        200: ProposalResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Conflict: the user state is outdated, please fetch the pending proposals first.
         */
        409: unknown;
        /**
         * Internal Server Error
         */
        500: unknown;
      };
    };
    patch: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
        formData: ApplicationMessageRequest;
      };
      res: {
        /**
         * Added application message.
         */
        200: unknown;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Not found.
         */
        404: unknown;
        /**
         * Internal Server Error
         */
        500: unknown;
      };
    };
  };
  '/folders/{folder_id}/proposals/{message_id}': {
    delete: {
      req: {
        /**
         * The folder id.
         */
        folderId: number;
        /**
         * The message to delete.
         */
        messageId: number;
      };
      res: {
        /**
         * Message removed from the queue.
         */
        200: unknown;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Not found.
         */
        404: unknown;
        /**
         * Internal Server Error, couldn't delete the message
         */
        500: unknown;
      };
    };
  };
  '/users': {
    get: {
      res: {
        /**
         * List of users using the SSF.
         */
        200: ListUsersResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Internal Server Error, couldn't retrieve the users
         */
        500: unknown;
      };
    };
    post: {
      req: {
        requestBody: CreateUserRequest;
      };
      res: {
        /**
         * New account created.
         */
        201: unknown;
        /**
         * Bad request.
         */
        400: unknown;
        /**
         * Unauthorized user, please, set a valid client credential.
         */
        401: unknown;
        /**
         * Conflict.
         */
        409: unknown;
      };
    };
  };
  '/users/keys': {
    post: {
      req: {
        formData: CreateKeyPackageRequest;
      };
      res: {
        /**
         * New key package created.
         */
        201: unknown;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Internal Server Error
         */
        500: unknown;
      };
    };
  };
  '/v2/folders/{folder_id}': {
    patch: {
      req: {
        /**
         * Folder id.
         */
        folderId: number;
        formData: ShareFolderRequestWithProposal;
      };
      res: {
        /**
         * Folder shared.
         */
        200: ProposalResponse;
        /**
         * Unkwown or unauthorized user.
         */
        401: unknown;
        /**
         * Not found.
         */
        404: unknown;
        /**
         * Conflict: client status out of sync.
         */
        409: unknown;
        /**
         * Internal Server Error, couldn't retrieve the users
         */
        500: unknown;
      };
    };
  };
};
