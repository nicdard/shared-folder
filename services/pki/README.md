# PKI server

A simple server to absract the CA and later also to implement part of the AS.

Uses rustls and rcgen libraries to manage x509 certificates.

* this CA/AS as the root of the chain of trust, exposing apis to:
    * register new identities
    * verify an identity
    ...

Applications should be able to run in two ways:
* embed the pk of the CA inside the application so that they can verify without a network call (for benchmarking)
* call the CA to verify the identities

## OpenApi
We use openapi to document our PKI service api and automatically generate client code for it.

To re-generate the [pki-openapi.yaml](../../openapi/pki-openapi.yaml) file (and add a license on top of it), use:
```bash
cargo run --package pki --bin gen_api
licensure --project 
```
You can then re-generate the rust client for pki service, using the [openapi.sh](../../openapi/openapi.sh) script.

## Swagger UI

You can try the server api using the Swagger UI at `/swagger-ui`

## Logging

Logging is available through the `log` facade, backed by the [`env_logger`](https://docs.rs/env_logger/latest/env_logger/) library. To enable logging, just add the `RUST_LOG=<level>` environment variable before the `cargo run` command.

## Binaries

The pki comes with [3 binaries](./src/bin):
* [main.rs](./src/bin/main.rs): The PKI server, you can simply run it through cargo:
```sh
RUST_LOG=<level> cargo run --package pki --bin main
```
* [gen_cr.rs](./src/bin/gen_cr.rs): A utility program to generate a PEM encoded to be used to test the register endpoint through Swagger UI:
```sh
RUST_LOG=debug cargo run --package pki --bin gen_cr
```
* [gen_api.rs](./src/bin/gen_api.rs): A utility program to generate the openapi spec in yaml under the [`openapi` folder](../../openapi/pki-openapi.yml). You should run it after changing the api of the PKI server.
```sh
cargo run --package pki --bin gen_api
```

The security of the SSF enforces only at the level of End-to-End encryption of the files stored in the storage.
The SSF server instead provides authentication and ACL security. For example, for an external user, it would be impossible to read a file of a shared folder if he is not part of the group, i.e. access to the folders is restricted by ACL enforced by the SSF.

## Cryptographic Stack

See the post from `Linkerd`: https://linkerd.io/2020/07/23/under-the-hood-of-linkerds-state-of-the-art-rust-proxy-linkerd2-proxy/
An audit requested by the Cloud Native Computing Foundation (CNCF) found that:
* [rustls](https://github.com/rustls/rustls), it also supports `aws-lc-rs` crypto provider.
* [ring](https://github.com/briansmith/ring)
* [webpki](https://github.com/briansmith/webpki)
are all exceptionally high quality, with the auditors from Cure53 "incredibly impressed with the presented software"

## Server stack

* Tokio, Rust’s asynchronous runtime,
* Hyper, a fast, safe, and correct HTTP implementation,
* Rustls, a secure, modern TLS implementation,
* Tower, a library of modular and composable components for networking software.
* Rocket, a web development framework, supporting TLS and mTLS

## Other resources and explorations:
* https://gist.github.com/Soarez/9688998 (guide on TLS and mTLS)
* use Warp with mTLS: https://github.com/camelop/rust-mtls-example?tab=readme-ov-file
* reqwest docs for mTLS: https://docs.rs/reqwest/0.11.4/reqwest/struct.ClientBuilder.html#method.identity
* warp docs: https://docs.rs/warp/0.3.1/warp/struct.TlsServer.html#method.client_auth_required_path
* axum: https://github.com/tokio-rs/axum
* OAuth

## TODOs:
* add CI to verify spec is up to date 
* use https://schemathesis.readthedocs.io/en/stable/index.html (see https://identeco.de/en/blog/generating_and_validating_openapi_docs_in_rust/)
* enable mTLS, or use other authentication procedure for all endpoints apart from `register` which is public to issue certificates. 
  * This can be done in Rocket with a `Certificate` guard, which also gives access in the handler to the Client certificate: https://api.rocket.rs/v0.5/rocket/mtls/struct.Certificate
  * Another solution would have been to use NGNIX

