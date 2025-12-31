// This module is the CJS entry point for the library.

import { EventEmitter } from 'events';
import * as addon from './load.cjs';

// Declare the addon functions (Neon exports camelCase names)
declare module "./load.cjs" {
  function browseServices(
    serviceType: string,
    callback: (event: string, data: unknown) => void
  ): number;
  function stopBrowse(handle: number): boolean;
  function advertiseService(
    name: string,
    serviceType: string,
    port: number,
    txt: Record<string, string> | undefined,
    callback: (event: string, data: unknown) => void
  ): number;
  function stopAdvertise(handle: number): boolean;
  function getBackendInfo(): string;
}

const DEBOUNCE_TIMEOUT = 100;

// Types
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

export type AdvertiseOptions = {
  name: string;
  type: string;
  domain?: string;
  hostName?: string;
  port: number;
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

  constructor(serviceType: string) {
    super();
    this._handle = addon.browseServices(serviceType, (event, data) => {
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

          // Debounce emit - wait 100ms for more addresses to arrive
          const existingTimeout = this._pendingEmit.get(key);
          if (existingTimeout) {
            clearTimeout(existingTimeout);
          }
          const timeout = setTimeout(() => {
            this._pendingEmit.delete(key);
            const svc = this._services.get(key);
            if (svc && !this._stopped && svc.addresses.length > 0) {
              this.emit('serviceFound', { ...svc });
            }
          }, DEBOUNCE_TIMEOUT);
          this._pendingEmit.set(key, timeout);
          break;
        }
        case 'serviceLost': {
          const lost = data as Service;
          const key = `${lost.name}|${lost.type}|${lost.domain}`;
          const service = this._services.get(key);
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
          this.emit('error', new Error(data as string));
          break;
      }
    });
  }

  stop(): void {
    if (!this._stopped) {
      this._stopped = true;
      // Clear all pending timeouts
      for (const timeout of this._pendingEmit.values()) {
        clearTimeout(timeout);
      }
      this._pendingEmit.clear();
      addon.stopBrowse(this._handle);
    }
  }
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
  }

  stop(): void {
    if (!this._stopped) {
      this._stopped = true;
      addon.stopAdvertise(this._handle);
    }
  }
}

// Main DnsSd class with static methods
export class DnsSd {
  static search(serviceType: string): DnsSdBrowse {
    return new DnsSdBrowse(serviceType);
  }

  static advertise(options: AdvertiseOptions): DnsSdAdvertisement {
    return new DnsSdAdvertisement(options);
  }

  static getBackendInfo(): string {
    return addon.getBackendInfo();
  }
}

export default DnsSd;
