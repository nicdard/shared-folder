# SSF server (Also known as DS)

This is a simple server of our imaginary company selling secure cloud storage.
The server is managing ACLs to the folders and the communication with the Cloud Storage.

## Testing

The server has [automated integration tests](/services/ds/tests/endpoints_test.rs) for all endpoints.
To run them first you will also need to generate the CA and this server certificates under the [private folder](../../private/)

To do so simply start the [pki server](../pki/README.md). A complete sequence of commands (all to be executed in the [project root](../../)):

Start the MySql databases (for PKI and SSF servers)
```bash
docker compose -f services/docker-compose.yaml up
```

In a separate shell, start the PKI to generate the certificates (if you already have them in the [private folder](../../private/) you can skip this step):
```bash
RUST_LOG=debug cargo run --package pki --bin main
```

Once the certificates are generated and stored on your local file system, you can shutdown the PKI server.
This automated tests are not interacting with the PKI for the client certificate generation, but just using
some of the functions defined in the [PKI crypto module](../../services/pki/src/crypto.rs) to create them
on the fly. Full automated E2Es are planned later, using the real client.

Now, run the E2Es:
```bash
RUST_LOG=debug cargo test --package ds
```

Since the tests are based on randomized input, they could fail in theory on clashing generated user names. In practice, on a fresh db instance, this is
really unlikely, as we use 50 chars long random strings, so the probability of collisions is really low.
Another option would have been to use [sqlx testing features](https://docs.rs/sqlx/latest/sqlx/attr.test.html) but it seems to have problems with 
the InnoDB engine. Also to be able to perform the tests with `Rocket`, this approach requires further integration between the libary 
and the framework: https://wtjungle.com/blog/integration-testing-rocket-sqlx/

## Configurations

The server can be configured in it's [DS_Rocket.toml](../../DS_Rocket.toml) configuration file. This needs to reside at top level, as we
have a cargo workspace and we run the commands from the root.
See the [Rocket documentation](https://rocket.rs/guide/v0.5/configuration/) for the available options 

## Logging

Logging is available through the `log` facade, backed by the [`env_logger`](https://docs.rs/env_logger/latest/env_logger/) library. To enable logging, just add the `RUST_LOG=<level>` environment variable before the `cargo run` command.

## Swagger UI

You can check in the [configuration](../../DS_Rocket.toml) the address and port to connect to the server (over https).
You can try the server api using the Swagger UI at `/swagger-ui`

## MySQL DB

The server connects to a MySQL instance, and you can find the setup script for the [creation of the tables in the `sql` folder](../sql/ds_database.sql)

## Server stack

* Tokio, Rust’s asynchronous runtime,
* Hyper, a fast, safe, and correct HTTP implementation,
* Rustls, a secure, modern TLS implementation,
* Tower, a library of modular and composable components for networking software.
* Rocket, a web development framework, supporting TLS and mTLS
