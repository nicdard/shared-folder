# Common rust dependencies

This is a rust lib, to be compiled as Webassembly and used as a common dependency
for the Typescript clients (Web and Nodejs).

## Build with wasm-pack

You need wasm-pack installed. Check out the [installation page](https://rustwasm.github.io/wasm-pack/installer/). Then run the following commands, to generate the libraries to be used
in the Browser and NodeJs environments:

```bash
wasm-pack build
wasm-pack build --target nodejs --out-dir nodejs
```

The `pkg` and `nodejs` folders will be created containing the npm package to be consumed in Browser and NodeJs environments respectively.
