// This module is the CJS entry point for the library.

import { EventEmitter } from 'events';
import * as addon from './load.cjs';

// Declare the addon functions (Neon exports camelCase names)
declare module "./load.cjs" {
  function browseServices(
    serviceType: string,
    domain: string | undefined,
    callback: (event: string, data: unknown) => void
  ): number;
  function stopBrowse(handle: number): boolean;
  function setBrowseRef(handle: number, referenced: boolean): boolean;
  function advertiseService(
    name: string,
    serviceType: string,
    domain: string | undefined,
    hostName: string | undefined,
    port: number,
    txt: Record<string, string> | undefined,
    callback: (event: string, data: unknown) => void
  ): number;
  function stopAdvertise(handle: number): boolean;
  function setAdvertiseRef(handle: number, referenced: boolean): boolean;
  function getBackendInfo(): string;
}

const DEBOUNCE_TIMEOUT = 100;
// How long to keep waiting for a service's addresses before emitting it anyway,
// so a service whose host has no A/AAAA record is still reported rather than
// silently dropped.
const ADDRESS_GRACE_TIMEOUT = 3000;

// Types
/**
 * A discovered service.
 *
 * `type`, `domain` and `hostName` are reported in the fully qualified form the
 * platform DNS-SD APIs use, with a trailing dot: `_http._tcp.`, `local.`,
 * `my-machine.local.`. Both backends report them identically.
 */
export type Service = {
  name: string;
  type: string;
  domain: string;
  hostName: string;
  addresses: string[];
  port: number;
  txt?: Record<string, string>;
  ttl?: number;
};

export type BrowseOptions = {
  /**
   * Domain to browse, defaulting to the daemon's own default (`local.`).
   *
   * `local` is mDNS (RFC 6762) and works on every backend. Any other domain -
   * `home.arpa` (RFC 8375), `lan`, a company domain - is resolved over unicast
   * DNS (RFC 6763 section 1), which only the native backends can do and which
   * needs a DNS server actually serving those records.
   */
  domain?: string;
};

export type AdvertiseOptions = {
  name: string;
  /** Service type, e.g. `_http._tcp` (a trailing dot is accepted too). */
  type: string;
  /**
   * Domain to advertise in, defaulting to `local.`.
   *
   * Anything other than `local` is unicast DNS-SD: native backends only, and
   * the domain's DNS server has to accept DNS Update (RFC 2136).
   */
  domain?: string;
  /**
   * SRV target host name. Defaults to this machine's host name.
   * A bare name is qualified into the `.local.` domain.
   */
  hostName?: string;
  /** Port, an integer between 0 and 65535. */
  port: number;
  /**
   * TXT records. Each `key=value` pair must stay within 255 bytes and must not
   * contain NUL bytes, per RFC 6763 section 6.1.
   */
  txt?: Record<string, string>;
};

// DnsSdBrowse class
export interface DnsSdBrowse {
  on(event: 'serviceFound', listener: (service: Service) => void): this;
  on(event: 'serviceLost', listener: (service: Service) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  emit(event: 'serviceFound', service: Service): boolean;
  emit(event: 'serviceLost', service: Service): boolean;
  emit(event: 'error', error: Error): boolean;
}

export class DnsSdBrowse extends EventEmitter {
  private _handle: number;
  private _stopped: boolean = false;
  private _services: Map<string, Service> = new Map();
  private _pendingEmit: Map<string, ReturnType<typeof setTimeout>> = new Map();
  private _firstSeen: Map<string, number> = new Map();

  constructor(serviceType: string, options: BrowseOptions = {}) {
    super();
    this._handle = addon.browseServices(serviceType, options.domain, (event, data) => {
      if (this._stopped) return;

      switch (event) {
        case 'serviceFound': {
          const incoming = data as Service;
          const key = `${incoming.name}|${incoming.type}|${incoming.domain}`;

          // Get or create service entry
          let service = this._services.get(key);
          if (service) {
            // Merge addresses (deduplicate)
            const allAddresses = new Set([...service.addresses, ...incoming.addresses]);
            // Normalize addresses, remove ends %eth-name
            service.addresses = Array.from(allAddresses).map(addr => addr.replace(/%[^%]+$/, ''));
            // Update other fields in case they changed
            service.hostName = incoming.hostName;
            service.port = incoming.port;
            if (incoming.txt) {
              service.txt = { ...service.txt, ...incoming.txt };
            }
            if (incoming.ttl) {
              service.ttl = incoming.ttl;
            }
          } else {
            service = { ...incoming };
            // Normalize addresses, remove ends %eth-name
            service.addresses = Array.from(service.addresses).map(addr => addr.replace(/%[^%]+$/, ''));
            this._services.set(key, service);
          }

          const firstSeen = this._firstSeen.get(key) ?? Date.now();
          this._firstSeen.set(key, firstSeen);

          // Debounce emit - wait for more addresses to arrive before reporting
          const existingTimeout = this._pendingEmit.get(key);
          if (existingTimeout) {
            clearTimeout(existingTimeout);
          }
          this._scheduleEmit(key, firstSeen, DEBOUNCE_TIMEOUT);
          break;
        }
        case 'serviceLost': {
          const lost = data as Service;
          const key = `${lost.name}|${lost.type}|${lost.domain}`;
          const service = this._services.get(key);
          this._firstSeen.delete(key);
          if (service) {
            this._services.delete(key);
            // Clear any pending emit
            const timeout = this._pendingEmit.get(key);
            if (timeout) {
              clearTimeout(timeout);
              this._pendingEmit.delete(key);
            }
            this.emit('serviceLost', service);
          }
          break;
        }
        case 'error':
          this.emit('error', new Error(typeof data === 'string' ? data : String(data)));
          break;
      }
    });
  }

  /**
   * Emit a discovered service once its address list looks complete.
   *
   * Addresses trickle in one resolve callback at a time, so the emit is
   * debounced. A service that never reports an address is emitted anyway after
   * ADDRESS_GRACE_TIMEOUT rather than being dropped.
   */
  private _scheduleEmit(key: string, firstSeen: number, delay: number): void {
    const timeout = setTimeout(() => {
      this._pendingEmit.delete(key);
      const svc = this._services.get(key);
      if (!svc || this._stopped) return;

      const waited = Date.now() - firstSeen;
      if (svc.addresses.length > 0 || waited >= ADDRESS_GRACE_TIMEOUT) {
        this.emit('serviceFound', { ...svc });
        return;
      }
      this._scheduleEmit(key, firstSeen, Math.min(DEBOUNCE_TIMEOUT * 4, ADDRESS_GRACE_TIMEOUT - waited));
    }, delay);
    // Never hold the event loop open just for a pending emit
    timeout.unref?.();
    this._pendingEmit.set(key, timeout);
  }

  /** Whether `stop()` has run. Mirrors `socket.destroyed`. */
  get stopped(): boolean {
    return this._stopped;
  }

  /**
   * Stop browsing and release the native handle. Stopping twice is a no-op.
   *
   * Teardown is synchronous and finished when this returns.
   */
  stop(): void {
    if (this._stopped) return;
    this._stopped = true;
    // Clear all pending timeouts
    for (const timeout of this._pendingEmit.values()) {
      clearTimeout(timeout);
    }
    this._pendingEmit.clear();
    this._firstSeen.clear();
    addon.stopBrowse(this._handle);
  }

  /** Stop holding the Node event loop open. Mirrors `timer.unref()`. */
  unref(): this {
    if (!this._stopped) addon.setBrowseRef(this._handle, false);
    return this;
  }

  /** Hold the Node event loop open again after `unref()`. */
  ref(): this {
    if (!this._stopped) addon.setBrowseRef(this._handle, true);
    return this;
  }

  /** Alias of `stop()`, so `using browser = DnsSd.search(...)` cleans up. */
  [Symbol.dispose](): void {
    this.stop();
  }
}

/**
 * Live advertisements, withdrawn on normal process exit.
 *
 * The native backends hand registration to a daemon, which withdraws a service
 * when its client disconnects. The mdns-sd fallback answers queries in-process,
 * so quitting without a goodbye packet leaves other hosts caching a service that
 * is already gone, until its TTL expires. Stopping them here costs nothing at
 * exit and keeps both backends behaving the same.
 */
const liveAdvertisements = new Set<DnsSdAdvertisement>();
let exitHookInstalled = false;

function trackAdvertisement(ad: DnsSdAdvertisement): void {
  liveAdvertisements.add(ad);
  if (exitHookInstalled) return;
  if (typeof process === 'undefined' || typeof process.on !== 'function') return;
  exitHookInstalled = true;
  process.on('exit', () => {
    for (const live of liveAdvertisements) {
      try {
        live.stop();
      } catch {
        // Already exiting; nothing useful left to do.
      }
    }
  });
}

// DnsSdAdvertisement class
export interface DnsSdAdvertisement {
  on(event: 'registered', listener: (name: string) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  emit(event: 'registered', name: string): boolean;
  emit(event: 'error', error: Error): boolean;
}

export class DnsSdAdvertisement extends EventEmitter {
  private _handle: number;
  private _stopped: boolean = false;

  constructor(options: AdvertiseOptions) {
    super();
    this._handle = addon.advertiseService(
      options.name,
      options.type,
      options.domain,
      options.hostName,
      options.port,
      options.txt,
      (event, data) => {
        if (this._stopped) return;

        switch (event) {
          case 'registered':
            this.emit('registered', data as string);
            break;
          case 'error':
            this.emit('error', new Error(data as string));
            break;
        }
      }
    );
    trackAdvertisement(this);
  }

  /** Whether `stop()` has run. Mirrors `socket.destroyed`. */
  get stopped(): boolean {
    return this._stopped;
  }

  /**
   * Stop advertising, unregister the service and release the native handle.
   * Stopping twice is a no-op.
   *
   * Teardown is synchronous and finished when this returns.
   */
  stop(): void {
    if (this._stopped) return;
    this._stopped = true;
    liveAdvertisements.delete(this);
    addon.stopAdvertise(this._handle);
  }

  /** Stop holding the Node event loop open. Mirrors `timer.unref()`. */
  unref(): this {
    if (!this._stopped) addon.setAdvertiseRef(this._handle, false);
    return this;
  }

  /** Hold the Node event loop open again after `unref()`. */
  ref(): this {
    if (!this._stopped) addon.setAdvertiseRef(this._handle, true);
    return this;
  }

  /** Alias of `stop()`, so `using ad = DnsSd.advertise(...)` unregisters. */
  [Symbol.dispose](): void {
    this.stop();
  }
}

// Main DnsSd class with static methods
export class DnsSd {
  static search(serviceType: string, options?: BrowseOptions): DnsSdBrowse {
    return new DnsSdBrowse(serviceType, options);
  }

  static advertise(options: AdvertiseOptions): DnsSdAdvertisement {
    return new DnsSdAdvertisement(options);
  }

  static getBackendInfo(): string {
    return addon.getBackendInfo();
  }
}

export default DnsSd;
