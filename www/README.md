# SSF Web Client

## Generate the fetch-based clients for the services

The Rust [services](../services/) [pki](../services/pki/README.md) and [ds](../services/ds/README.md) use OpenAPI. A specification of the servers can be generated and is stored in [openapi](../openapi/) folder. This project is using the module [hey-api](https://heyapi.vercel.app) to generate the clients programmatically for those servers from their spec files, as specified in [openapi.ts](./openapi.ts). You can just run the following command to re-generate the clients:

```bash
npm run openapi-ts
```

The clients are created under the folder [src/gen/clients](./src/gen/clients/). Please notice that the generated code is also versioned in git. This will help you identify any changes after re-generating the client. You should commit the changes to the auto-generated code as one only commit containing only this generated code.

## Trusting your self signed CA certificate

* https://stackoverflow.com/questions/27808548/verifying-a-self-signed-certificate-on-local-laravel-homestead-server/44060726#44060726
* in Chrome, you can disable a flag for localhost: visit `chrome://flags/` and set to ENABLED allow untrusted certificates for localhost
