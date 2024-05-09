# Common rust dependencies

This is a rust lib, to be compiled as Webassembly and used as a common dependency
for the Typescript clients (Web and Nodejs).

It is also used as a common dependency for our rust services.

The `lib.rs` is re-exporting the modules that are made accessible to the rust code, as well as
providing the required Webassembly bindings to generate the JS bindings to be used in our Typescript clients.

Just check the `lib.rs` file to see what bindings are avaialble when compiling to Webassembly.

## Build with wasm-pack

You need wasm-pack installed. Check out the [installation page](https://rustwasm.github.io/wasm-pack/installer/). Then run the following commands, to generate the libraries to be used
in the Browser and NodeJs environments:

```bash
wasm-pack build
wasm-pack build --target nodejs --out-dir nodejs
```

The `pkg` and `nodejs` folders will be created containing the npm package to be consumed in Browser and NodeJs environments respectively.

## Install the Rust lib

To install this package as a Rust lib dependency, just run at top level:

```bash
cargo add --package < name of the dependent crate > common
```
