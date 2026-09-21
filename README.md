# @fugood/dns-sd

[![npm version](https://img.shields.io/npm/v/@fugood/dns-sd.svg)](https://www.npmjs.com/package/@fugood/dns-sd)
[![npm downloads](https://img.shields.io/npm/dm/@fugood/dns-sd.svg)](https://www.npmjs.com/package/@fugood/dns-sd)
[![Test](https://github.com/mybigday/dns-sd/actions/workflows/test.yml/badge.svg)](https://github.com/mybigday/dns-sd/actions/workflows/test.yml)
[![license](https://img.shields.io/npm/l/@fugood/dns-sd.svg)](./LICENSE)

A powerful, cross-platform DNS-SD (Zeroconf/Bonjour/Avahi) library for Node.js, built with Rust.

`@fugood/dns-sd` provides a unified API for discovering and advertising services on the local network. It intelligently selects the best available backend:

*   **Native**: Uses the system's native DNS-SD implementation (Avahi on Linux, Bonjour on macOS/Windows) for optimal performance and compatibility.
*   **Fallback**: Automatically degrades to a pure Rust implementation (`mdns-sd`) if the native service is unavailable — whether the system library is missing *or* its daemon is not running, which is the usual case inside containers. The backend is picked per handle, so it follows the daemon coming and going.

## Features

*   🚀 **High Performance**: Native bindings via Neon for low overhead.
*   🔄 **Dual Backend**: Robust fallback mechanism ensures your app works everywhere.
*   📦 **Zero Configuration**: Works out of the box without complex setup.
*   📡 **Discovery & Advertising**: Support for both browsing and publishing services.
*   📝 **TypeScript Support**: First-class types included.

## Installation

```bash
npm install @fugood/dns-sd
```

The package is published under the **`@fugood`** scope, so the scope is required both when
installing and when importing — there is no unscoped `dns-sd` package on npm.

Prebuilt binaries are pulled in automatically as optional dependencies, one per platform:

| Platform | Package |
| --- | --- |
| Windows x64 | [`@fugood/dns-sd-win32-x64-msvc`](https://www.npmjs.com/package/@fugood/dns-sd-win32-x64-msvc) |
| Windows arm64 | [`@fugood/dns-sd-win32-arm64-msvc`](https://www.npmjs.com/package/@fugood/dns-sd-win32-arm64-msvc) |
| macOS x64 | [`@fugood/dns-sd-darwin-x64`](https://www.npmjs.com/package/@fugood/dns-sd-darwin-x64) |
| macOS arm64 | [`@fugood/dns-sd-darwin-arm64`](https://www.npmjs.com/package/@fugood/dns-sd-darwin-arm64) |
| Linux x64 (glibc) | [`@fugood/dns-sd-linux-x64-gnu`](https://www.npmjs.com/package/@fugood/dns-sd-linux-x64-gnu) |
| Linux arm64 (glibc) | [`@fugood/dns-sd-linux-arm64-gnu`](https://www.npmjs.com/package/@fugood/dns-sd-linux-arm64-gnu) |

## Usage

### Discover Services

Browsing for services is simple. Use the `search` method to start listening for services of a specific type.

```typescript
import DnsSd, { Service } from '@fugood/dns-sd';

// Search for HTTP services
const browser = DnsSd.search('_http._tcp');

browser.on('serviceFound', (service: Service) => {
  console.log('Found service:', service.name);
  console.log('IP Addresses:', service.addresses);
  console.log('Port:', service.port);
  if (service.txt) {
    console.log('TXT Records:', service.txt);
  }
});

browser.on('serviceLost', (service: Service) => {
  console.log('Lost service:', service.name);
});

browser.on('error', (err) => {
  console.error('Browser error:', err);
});

// Stop browsing after 30 seconds
setTimeout(() => {
  browser.stop();
}, 30000);
```

### Advertise a Service

Publish your own service to the network using `advertise`.

```typescript
import DnsSd, { DnsSdAdvertisement } from '@fugood/dns-sd';

const ad = DnsSd.advertise({
  name: 'My Cool Service',
  type: '_http._tcp',
  port: 8080,
  txt: {
    version: '1.0.0',
    path: '/api'
  }
});

ad.on('registered', (name) => {
  console.log(`Service registered successfully as "${name}"`);
});

ad.on('error', (err) => {
  console.error('Advertisement error:', err);
});

// Stop advertising when closing
// ad.stop();
```

### Check Backend

You can check which backend is currently active (dependent on system availability).

```typescript
import DnsSd from '@fugood/dns-sd';

console.log('Current Backend:', DnsSd.getBackendInfo());
// Outputs: "bonjour", "native" (Avahi), or "mdns-sd"
```

## API Reference

### `DnsSd`

The main entry point.

*   `static search(serviceType: string, options?: BrowseOptions): DnsSdBrowse`: Start a browser for the given service type (e.g., `_http._tcp`).
*   `static advertise(options: AdvertiseOptions): DnsSdAdvertisement`: Start advertising a service.
*   `static getBackendInfo(): string`: Returns the name of the active backend.

### `DnsSdBrowse`

Emits events for service discovery.

**Events:**
*   `'serviceFound'`: Emitted when a service is discovered or updated. Payload: `Service`.
*   `'serviceLost'`: Emitted when a service goes offline. Payload: `Service`.
*   `'error'`: Emitted on failure, including when the browse dies on its own because the
    system DNS-SD daemon went away. Payload: `Error`. Attach a listener: an `'error'` with
    no listener throws, as on any `EventEmitter`.

**Methods:**
*   `stop()`: Stops the browser and releases its native handle and polling thread.
    Teardown is synchronous and complete when it returns; stopping twice is a no-op.
*   `unref()` / `ref()`: Exclude the browser from — or add it back to — the reference
    count that keeps the Node process alive.
*   `[Symbol.dispose]()`: Alias of `stop()`, so `using browser = DnsSd.search(...)` cleans
    up on scope exit. The method exists on every supported Node version; the `using`
    syntax itself needs Node 24+.

**Properties:**
*   `stopped`: `true` once `stop()` has run.

### `DnsSdAdvertisement`

Manages a published service.

**Events:**
*   `'registered'`: Emitted when the service is registered, carrying the name actually in
    use. If the name was already taken it is renamed to `Name (2)` per RFC 6762 section 9,
    on every backend. A conflict detected after registration re-emits this event with the
    new name, so always use the name from the latest event.
*   `'error'`: Emitted on failure, including when the advertisement dies on its own
    because the system DNS-SD daemon went away — the service is no longer published at
    that point, so recreate it. Payload: `Error`.

**Methods:**
*   `stop()`: Stops advertising, unregisters the service and releases its native handle.
    Teardown is synchronous and complete when it returns; stopping twice is a no-op.
*   `unref()` / `ref()`: Exclude the advertisement from — or add it back to — the
    reference count that keeps the Node process alive.
*   `[Symbol.dispose]()`: Alias of `stop()`, so `using ad = DnsSd.advertise(...)`
    unregisters on scope exit (the `using` syntax needs Node 24+).

**Properties:**
*   `stopped`: `true` once `stop()` has run.

Live advertisements are withdrawn on normal process exit even if you never call `stop()`,
so other hosts do not keep a dead service cached.

### Lifecycle

A live browser or advertisement keeps the process alive, like an open handle in Node's own
`net` and `dgram` modules. `unref()` opts out of that and `ref()` opts back in; both return
the object so calls chain, and both are safe to call repeatedly or after `stop()`.

There is no `'close'` event: `stop()` is synchronous and local, so it is finished when it
returns. Teardown you did *not* ask for — the system daemon dying — arrives as an
`'error'` instead, because that is the case you cannot see coming.

```typescript
const browser = DnsSd.search('_http._tcp').unref(); // won't hold the process open
browser.on('error', (err) => console.error('browse died:', err.message));
browser.stop();

// or let the scope do it
using ad = DnsSd.advertise({ name: 'My Service', type: '_http._tcp', port: 8080 });
```

### Types

#### `Service`
```typescript
interface Service {
  name: string;        // Instance name, e.g. "My Printer"
  type: string;        // "_http._tcp."
  domain: string;      // "local."
  hostName: string;    // "my-machine.local."
  addresses: string[]; // IPv4 and IPv6 addresses
  port: number;
  txt?: Record<string, string>;
  ttl?: number;
}
```

`type`, `domain` and `hostName` are reported in the fully qualified form the platform
DNS-SD APIs use, with a trailing dot — the same strings on every backend, so you can
compare them across platforms. Browsing a subtype still reports the base `type`.

`ttl` is only present when the backend reports one; the `mdns-sd` fallback does not
expose it.

A service is emitted once its addresses have been collected. One whose host advertises no
address is still emitted, after a short grace period, with an empty `addresses` array.

#### `BrowseOptions`
```typescript
interface BrowseOptions {
  domain?: string;     // defaults to "local." — see Domains below
}
```

#### `AdvertiseOptions`
```typescript
interface AdvertiseOptions {
  name: string;
  type: string;        // "_http._tcp" — a trailing dot is accepted too
  domain?: string;     // defaults to "local." — see Domains below
  hostName?: string;   // SRV target, defaults to this machine; "my-host" is
                       // qualified to "my-host.local."
  port: number;        // integer, 0-65535
  txt?: Record<string, string>;
}
```

Invalid input throws synchronously from `advertise()` and `search()`, with the same
message on every backend:

*   a service name that is empty or over 63 bytes — a DNS label limit, so non-ASCII names
    hit it sooner (a CJK character is 3 bytes)
*   any host name, domain or service type label over 63 bytes
*   a service type that is not of the form `_http._tcp` / `_http._udp`
*   a port outside 0-65535, or with a fractional part
*   TXT entries that are empty-keyed, contain NUL bytes, or whose `key=value` pair exceeds
    the 255 byte limit from RFC 6763 section 6.1

Subtypes use the Bonjour spelling on both backends: `_http._tcp,_printer` advertises or
browses the `_printer` subtype. The `mdns-sd` fallback supports one subtype per service.

A `hostName` that no host answers for makes the service unresolvable — it will be
announced but browsers will not be able to resolve it.

## Domains

DNS-SD itself is transport-independent — RFC 6763 is "compatible with both Multicast DNS
and with today's existing Unicast DNS server and client software" — so the domain decides
how lookups actually travel:

*   **`local.` (the default)** is multicast DNS, RFC 6762. Zero configuration, and every
    backend supports it. This is what you want on a LAN.
*   **Any other domain** — `home.arpa.` (RFC 8375), `lan.`, `home.`, a company domain — is
    plain unicast DNS. RFC 8375 is explicit that `home.arpa` "does not require a special
    resolution protocol" and is resolved with ordinary DNS, so these names are *not*
    answered by mDNS at all. Records have to exist on the DNS server that serves the
    domain, and advertising into it needs DNS Update (RFC 2136).

```typescript
// mDNS on the local link (default)
DnsSd.search('_http._tcp');

// Wide-area DNS-SD against a unicast domain
DnsSd.search('_http._tcp', { domain: 'home.arpa' });
```

What each backend does with a non-`local` domain:

| Backend | Non-`local` domain |
| --- | --- |
| `bonjour` (macOS/Windows) | Accepted — queries/registers over unicast DNS |
| `native` (Linux, Avahi compat) | Rejected by the daemon; surfaces as an `'error'` event or a throw |
| `mdns-sd` (fallback) | Rejected up front with an explanatory error — mDNS serves `local.` only |

## Contributing

This project uses `cargo` for the Rust backend and `npm` for the Node.js frontend.

1.  **Install Dependencies**: `npm install`
2.  **Build**: `npm run build`
3.  **Test**: `npm test`

Licensed under the [MIT License](./LICENSE).

## Links

*   [npm package](https://www.npmjs.com/package/@fugood/dns-sd)
*   [Source code](https://github.com/mybigday/dns-sd)
*   [Issue tracker](https://github.com/mybigday/dns-sd/issues)
*   [Changelog / releases](https://github.com/mybigday/dns-sd/releases)

---

<p align="center">
  <a href="https://bricks.tools">
    <img width="90px" src="https://avatars.githubusercontent.com/u/17320237?s=200&v=4">
  </a>
  <p align="center">
    Built and maintained by <a href="https://bricks.tools">BRICKS</a>.
  </p>
</p>

