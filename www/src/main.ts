import { import_wasm } from './import_wasm';


void (async () => {
  const module = await import_wasm();
  module.greet('CIAO');
})();
