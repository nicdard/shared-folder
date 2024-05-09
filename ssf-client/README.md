# SSF Client

This is a Typescript/Node implementation of the SSF client.

The client assumes that the CA certificate is shipped with the application code. See the command (defined in [package.json](./package.json)):

```bash
npm run copy-private-files
```

This is not good for production use cases (as certificates can expire), but the current certificate setup is ok for demonstation purposes.
However, a method to download a new version of the CA certificate is available in the CLI commands, but users must run it
before the CA certificate expires, or they are forced to get the same with other means. This is only because we are using self-signed certificates for our CA server, in a real installation the CA server would have a real Certificate such as one provided by [Let's Encrypt](https://letsencrypt.org).
See the CLI help for more details, in particular `ca-cert` command.

## Interactive mode

The CLI can be used in interactive mode passing the `-i` or `--interactive` option to the main `ssf-client` command.
This way, the user will enter a REPL where to insert the commands, which also maintains the history of previous commands for the session.

To run locally an interactive session:

```bash
npm run start -- -i
```

## Dependencies

You will need to generate the Webassembly module from [`common`](../common/README.md) rust package to be able to install all the required dependencies. See the README.md file for the required commands.

Then run:
```bash
npm install
```

To use this CLI locally, please run the [services](../services/), in execution order:

- start the [docker-compose](../services/docker-compose.yaml) containers
- start the [PKI server](../services/pki/README.md)
- start the [DS server](../services/ds/README.md)

## Generated code

The clients to connect to the `PKI` and `DS` servers are generated from the openapi specification stored in [openapi](../openapi/) folder.

You can re-generate them using:

```bash
npm run openapi-ts
```

Note: the generated code is versioned in git to help detecting any differences.

The clients rely on `axios` library to be compatible across Node and Web broswers environments, see also [www](../www).
The plan is to make the CLI only a presentation layer, and re-use as much code as possible between this and the `www` package.

## State

The CLI has stateful commands. Those commands are saving data to disk inside the `/private` folder under the installation path of the application. When running locally through `npm`, you will be able to see the state inside [./dist/private](./dist/private/) folder.

## Installing the CLI in your system

If you want to add the CLI locally to your PATH to make it available in the terminal, you can run:

```bash
npm link
```

The CLI will be added as `ssf-client` command.

Remember to cleanup afterwards:

```bash
npm unlink ssf-client
```

## References

### CLI development

https://medium.com/nmc-techblog/building-a-cli-with-node-js-in-2024-c278802a3ef5
https://github.com/lirantal/nodejs-cli-apps-best-practices

## Testing

https://javascript.plainenglish.io/how-to-test-a-node-js-command-line-tool-2735ea7dc041
https://github.com/tj/commander.js/issues/1565

### Binary

https://medium.com/netscape/a-guide-to-create-a-nodejs-command-line-package-c2166ad0452e
