# SSF protocol Rust to WASM lib

This is a rust lib, to be compiled as Webassembly and used as a common dependency
for the Typescript clients (Web and Nodejs).

In this lib, we provide bindings to use AWS mls-rs library mainly, to implement GRaPPA.

## Build with wasm-pack

You need wasm-pack installed. Check out the [installation page](https://rustwasm.github.io/wasm-pack/installer/). Then run the following commands, to generate the libraries to be used
in the Browser and NodeJs environments:

```bash
RUSTFLAGS="--cfg mls_build_async" wasm-pack build
RUSTFLAGS="--cfg mls_build_async" wasm-pack build --target nodejs --out-dir nodejs
```

NOTE: you will need to use a version of the compiler infrastructure that supports `wasm32`. If you are developing on MacOS, please verify you are using LLVM clang (and not Apple clang):

```bash
$ clang --version
Homebrew clang version 18.1.5
Target: arm64-apple-darwin23.2.0
Thread model: posix
InstalledDir: /opt/homebrew/opt/llvm/bin
```

If this is not the case, install LLVM compiler using:

```bash
brew install llvm
```

And follow the instructions to make it the default compiler that are printed in the terminal at the end of the installation.

If the above command are successful, the `pkg` and `nodejs` folders will be created containing the npm package to be consumed in Browser and NodeJs environments respectively.

## Tests

### Node

To run the wasm tests inside NodeJs, use the following command:

```bash
RUSTFLAGS="--cfg mls_build_async" wasm-pack test --node
```

Be sure to have the **default features** activated for the `mls-rs-crypto-webcrypto` dependency.

### Safari

To run the wasm tests inside Safari:

- uncomment the `wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);` line or add it to the tests you want to run
- execute the following:

```bash
RUSTFLAGS="--cfg mls_build_async" wasm-pack test --safari --headless
```

Be sure not to have the **node** feature activated for the `mls-rs-crypto-webcrypto` and `mls-rs-core` dependency.

### Chrome

To start the tests in chrome, you need to download a chromedriver (if you are on an Apple M1 machine):
https://chromedriver.storage.googleapis.com/index.html?path=114.0.5735.90/

then you need to set the path variable as descibed in the [guide](https://rustwasm.github.io/wasm-bindgen/wasm-bindgen-test/browsers.html):

```bash
CHROMEDRIVER=path/to/chromedriver
```

- uncomment the `wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);` line or add it to the tests you want to run
- execute the following:

```bash
RUSTFLAGS="--cfg mls_build_async" cargo test --target wasm32-unknown-unknown -- --nocapture
```

Be sure to have the **node** feature activated for the `mls-rs-crypto-webcrypto` and `mls-rs-core` dependency.
