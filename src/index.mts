// This module is the ESM entry point for the library.

export * from './index.cjs';
// Re-export the named `DnsSd` binding as the default export: Node's CJS/ESM
// interop maps `default` to the whole `module.exports` object, so forwarding
// `export { default } from './index.cjs'` would hand consumers the namespace
// object instead of the class.
export { DnsSd as default } from './index.cjs';
