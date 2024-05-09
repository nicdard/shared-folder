// This file is auto-generated by @hey-api/openapi-ts

export type GetCredentialRequest = {
  /**
   * The email of the client for which to get the credential.
   */
  email: string;
};

export type GetCredentialResponse = {
  /**
   * PEM encoded certificate.
   */
  certificate: string;
};

export type RegisterRequest = {
  /**
   * PEM encoded certificate request.
   */
  certificate_request: string;
  /**
   * The email contained in the [certificate_request].
   */
  email: string;
};

export type RegisterResponse = {
  /**
   * PEM encoded certificate.
   */
  certificate: string;
};

export type VerifyRequest = {
  /**
   * PEM encoded client certificate.
   */
  certificate: string;
};

export type VerifyResponse = {
  /**
   * Whether the certificate is valid.
   */
  valid: boolean;
};

export type $OpenApiTs = {
  '/api-doc.json': {
    get: {
      res: {
        /**
         * JSON file
         */
        200: unknown;
      };
    };
  };
  '/ca/credential': {
    get: {
      res: {
        /**
         * CA certificate
         */
        200: GetCredentialResponse;
      };
    };
  };
  '/ca/register': {
    post: {
      req: {
        requestBody: RegisterRequest;
      };
      res: {
        /**
         * Registered client.
         */
        201: RegisterResponse;
        /**
         * Bad Request
         */
        400: unknown;
        /**
         * Conflict
         */
        409: unknown;
      };
    };
  };
  '/ca/verify': {
    post: {
      req: {
        requestBody: VerifyRequest;
      };
      res: {
        /**
         * Whether the client's certificate is valid or not.
         */
        200: VerifyResponse;
      };
    };
  };
  '/credential': {
    post: {
      req: {
        requestBody: GetCredentialRequest;
      };
      res: {
        /**
         * client certificate
         */
        200: GetCredentialResponse;
        /**
         * Not Found
         */
        404: unknown;
      };
    };
  };
};
