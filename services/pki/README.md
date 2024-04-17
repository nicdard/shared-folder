# PKI server

A simple server to absract the CA and later AS.

Uses openssl library to manage x509 certificates.

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

## TODOs:
* add CI to verify spec is up to date 
* use https://schemathesis.readthedocs.io/en/stable/index.html (see https://identeco.de/en/blog/generating_and_validating_openapi_docs_in_rust/)
* do not encrypt data, as this is covered by TLS.
* enable mTLS, or use other authentication procedure for all endpoints apart from `register` which is public to issue certificates.
* if we want to use mTLS, we can either:
  * perform authentication at L5 (where we use the client certificate in the request), however, this needs to be retrieved in the server
  * use NGNIX to front the server, and set the client certificate in NGNIX inside the request as an HTTP header, to simplify management in the actual server


## Architecture:

As S3 storage is not publicly available, we organise the system in 3 main different components:
* CA server (PKI), to address security concerns for this we could also use `KeyTransparency` but it is out of scope for the thesis.
* Client application, each client creates a key pair for asymmetric encryption, and `register` to the CA 
  * we want to re-use this as a form of authentication as well, instead of having a password, so we would like to use mTLS.
* the SSF server, which is basically the company providing the storage. In our case, we offload the storage in S3. All the endpoints of the SSF are authenticated. The SSF server is further divided into different logical components:
  * DS: delivery service
  * AS: authentication service
  * Storage service (manages the folders and ACLs to them)

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

## Resources:
* https://gist.github.com/Soarez/9688998 (guide on TLS and mTLS)
* use Warp with mTLS: https://github.com/camelop/rust-mtls-example?tab=readme-ov-file
* reqwest docs for mTLS: https://docs.rs/reqwest/0.11.4/reqwest/struct.ClientBuilder.html#method.identity
* warp docs: https://docs.rs/warp/0.3.1/warp/struct.TlsServer.html#method.client_auth_required_path
