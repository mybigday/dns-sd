// This module loads the platform-specific build of the addon on
// the current system. The supported platforms are registered in
// the `platforms` object below, whose entries can be managed by
// by the Neon CLI:
//
//   https://www.npmjs.com/package/@neon-rs/cli

// Optional override, for layouts where neither branch below can find the
// addon. Resolved against cwd, not this module.
const overridePath = process.env.DNS_SD_NATIVE_LIBRARY_PATH;
if (overridePath) {
  module.exports = require(require('path').resolve(overridePath));
} else {

module.exports = require('@neon-rs/load').proxy({
  platforms: {
    'win32-x64-msvc': () => require('@fugood/dns-sd-win32-x64-msvc'),
    'win32-arm64-msvc': () => require('@fugood/dns-sd-win32-arm64-msvc'),
    'darwin-x64': () => require('@fugood/dns-sd-darwin-x64'),
    'darwin-arm64': () => require('@fugood/dns-sd-darwin-arm64'),
    'linux-x64-gnu': () => require('@fugood/dns-sd-linux-x64-gnu'),
    'linux-arm64-gnu': () => require('@fugood/dns-sd-linux-arm64-gnu'),
    'linux-x64-musl': () => require('@fugood/dns-sd-linux-x64-musl'),
    'linux-arm64-musl': () => require('@fugood/dns-sd-linux-arm64-musl')
  },
  // Built path, not a literal: this file is published without index.node, so
  // a static require('../index.node') is unresolvable in an installed package
  // and bundlers fail the build on it before any of this can run.
  debug: () => require(require('path').join(__dirname, '..', 'index.node'))
});

}
