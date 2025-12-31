# dns-sd

A powerful, cross-platform DNS-SD (Zeroconf/Bonjour/Avahi) library for Node.js, built with Rust.

`dns-sd` provides a unified API for discovering and advertising services on the local network. It intelligently selects the best available backend:

*   **Native**: Uses the system's native DNS-SD implementation (Avahi on Linux, Bonjour on macOS/Windows) for optimal performance and compatibility.
*   **Fallback**: Automatically degrades to a pure Rust implementation (`mdns-sd`) if the native service is unavailable.

## Features

*   🚀 **High Performance**: Native bindings via Neon for low overhead.
*   🔄 **Dual Backend**: Robust fallback mechanism ensures your app works everywhere.
*   📦 **Zero Configuration**: Works out of the box without complex setup.
*   📡 **Discovery & Advertising**: Support for both browsing and publishing services.
*   📝 **TypeScript Support**: First-class types included.

## Installation

```bash
npm install dns-sd
```

Prebuilt binaries are available for major platforms:
*   Windows (x64, arm64)
*   macOS (x64, arm64)
*   Linux (x64, arm64)

## Usage

### Discover Services

Browsing for services is simple. Use the `search` method to start listening for services of a specific type.

```typescript
import DnsSd, { Service } from 'dns-sd';

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
import DnsSd, { DnsSdAdvertisement } from 'dns-sd';

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
import DnsSd from 'dns-sd';

console.log('Current Backend:', DnsSd.getBackendInfo());
// Outputs: "bonjour", "native" (Avahi), or "mdns-sd"
```

## API Reference

### `DnsSd`

The main entry point.

*   `static search(serviceType: string): DnsSdBrowse`: Start a browser for the given service type (e.g., `_http._tcp`).
*   `static advertise(options: AdvertiseOptions): DnsSdAdvertisement`: Start advertising a service.
*   `static getBackendInfo(): string`: Returns the name of the active backend.

### `DnsSdBrowse`

Emits events for service discovery.

**Events:**
*   `'serviceFound'`: Emitted when a service is discovered or updated. Payload: `Service`.
*   `'serviceLost'`: Emitted when a service goes offline. Payload: `Service`.
*   `'error'`: Emitted on failure. Payload: `Error`.

**Methods:**
*   `stop()`: Stops the browser.

### `DnsSdAdvertisement`

Manages a published service.

**Events:**
*   `'registered'`: Emitted when the service is successfully registered with the daemon. Payload: `string` (registered name).
*   `'error'`: Emitted on failure. Payload: `Error`.

**Methods:**
*   `stop()`: Stops advertising.

### Types

#### `Service`
```typescript
interface Service {
  name: string;
  type: string;
  domain: string;
  hostName: string;
  addresses: string[]; // IPv4 and IPv6 addresses
  port: number;
  txt?: Record<string, string>;
  ttl?: number;
}
```

#### `AdvertiseOptions`
```typescript
interface AdvertiseOptions {
  name: string;
  type: string;
  domain?: string;
  hostName?: string;
  port: number;
  txt?: Record<string, string>;
}
```

## Contributing

This project uses `cargo` for the Rust backend and `npm` for the Node.js frontend.

1.  **Install Dependencies**: `npm install`
2.  **Build**: `npm run build`
3.  **Test**: `npm test`

Licensed under MIT.

---

<p align="center">
  <a href="https://bricks.tools">
    <img width="90px" src="https://avatars.githubusercontent.com/u/17320237?s=200&v=4">
  </a>
  <p align="center">
    Built and maintained by <a href="https://bricks.tools">BRICKS</a>.
  </p>
</p>

