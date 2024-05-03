// Terrible hack to get typescript to recognize the wasm module and its types.
export const import_wasm: () => Promise<typeof import('../node_modules/ssf/ssf')>;
