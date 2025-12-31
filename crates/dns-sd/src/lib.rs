//! Cross-platform DNS-SD with dynamic backend selection
//! 
//! Tries native backend (Avahi/Bonjour) first, falls back to mdns-sd if unavailable.

mod ffi;
mod native;
mod fallback;

use neon::prelude::*;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

// Re-export ServiceInfo
pub use native::ServiceInfo;

// Global handle counter
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

fn next_handle() -> u32 {
    NEXT_HANDLE.fetch_add(1, Ordering::SeqCst)
}

/// Backend type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Backend {
    Native,
    Fallback,
}

/// Check which backend is available
fn get_backend() -> Backend {
    if native::is_available() {
        Backend::Native
    } else {
        Backend::Fallback
    }
}

/// Get backend info as string
#[neon::export]
fn get_backend_info() -> String {
    match get_backend() {
        Backend::Native => {
            #[cfg(target_os = "macos")]
            { "bonjour".to_string() }
            #[cfg(target_os = "windows")]
            { "bonjour".to_string() }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            { "native".to_string() }
        }
        Backend::Fallback => "mdns-sd".to_string(),
    }
}

// Browser handles storage
enum BrowserHandle {
    Native(native::NativeBrowser),
    Fallback(fallback::FallbackBrowser),
}

static BROWSERS: Lazy<Mutex<HashMap<u32, BrowserHandle>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// Advertisement handles storage
enum AdvertisementHandle {
    Native(native::NativeAdvertisement),
    Fallback(fallback::FallbackAdvertisement),
}

static ADVERTISEMENTS: Lazy<Mutex<HashMap<u32, AdvertisementHandle>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Convert ServiceInfo to JS object
fn service_info_to_js<'cx>(
    cx: &mut impl Context<'cx>,
    info: &ServiceInfo,
) -> JsResult<'cx, JsObject> {
    let obj = cx.empty_object();
    
    let name = cx.string(&info.name);
    obj.set(cx, "name", name)?;
    
    let stype = cx.string(&info.service_type);
    obj.set(cx, "type", stype)?;
    
    let domain = cx.string(&info.domain);
    obj.set(cx, "domain", domain)?;
    
    let hostname = cx.string(&info.host_name);
    obj.set(cx, "hostName", hostname)?;
    
    let port = cx.number(info.port as f64);
    obj.set(cx, "port", port)?;
    
    let addrs = cx.empty_array();
    for (i, addr) in info.addresses.iter().enumerate() {
        let addr_val = cx.string(addr);
        addrs.set(cx, i as u32, addr_val)?;
    }
    obj.set(cx, "addresses", addrs)?;
    
    if !info.txt.is_empty() {
        let txt_obj = cx.empty_object();
        for (k, v) in &info.txt {
            let val = cx.string(v);
            txt_obj.set(cx, k.as_str(), val)?;
        }
        obj.set(cx, "txt", txt_obj)?;
    }
    
    let ttl = cx.number(info.ttl as f64);
    if info.ttl > 0 {
        obj.set(cx, "ttl", ttl)?;
    }
    
    Ok(obj)
}

/// Start browsing for services
#[neon::export]
fn browse_services<'cx>(
    cx: &mut FunctionContext<'cx>,
    service_type: String,
    callback: Handle<'cx, JsFunction>,
) -> NeonResult<Handle<'cx, JsNumber>> {
    let channel = cx.channel();
    let callback = std::sync::Arc::new(callback.root(cx));
    
    let handle_id = next_handle();
    
    // Create callback wrapper
    let make_callback = |channel: neon::event::Channel, callback: std::sync::Arc<neon::handle::Root<JsFunction>>| {
        move |event: &str, info: ServiceInfo| {
            let event = event.to_string();
            let callback = callback.clone();
            
            channel.send(move |mut cx| {
                let cb = callback.to_inner(&mut cx);
                let this = cx.undefined();
                let event_val = cx.string(&event);
                let info_obj = service_info_to_js(&mut cx, &info)?;
                let _ = cb.call(&mut cx, this, vec![event_val.upcast(), info_obj.upcast()]);
                Ok(())
            });
        }
    };

    let result = match get_backend() {
        Backend::Native => {
            native::NativeBrowser::new(&service_type, make_callback(channel, callback))
                .map(BrowserHandle::Native)
        }
        Backend::Fallback => {
            // Convert fallback::ServiceInfo to our ServiceInfo
            let cb = make_callback(channel, callback);
            fallback::FallbackBrowser::new(&service_type, move |event, info| {
                let converted = ServiceInfo {
                    name: info.name,
                    service_type: info.service_type,
                    domain: info.domain,
                    host_name: info.host_name,
                    addresses: info.addresses,
                    port: info.port,
                    txt: info.txt,
                    ttl: info.ttl,
                };
                cb(event, converted);
            }).map(BrowserHandle::Fallback)
        }
    };
    
    match result {
        Ok(browser) => {
            BROWSERS.lock().unwrap().insert(handle_id, browser);
            Ok(cx.number(handle_id as f64))
        }
        Err(e) => cx.throw_error(e),
    }
}

/// Stop browsing
#[neon::export]
fn stop_browse(handle_id: f64) -> bool {
    let handle_id = handle_id as u32;
    if let Some(mut browser) = BROWSERS.lock().unwrap().remove(&handle_id) {
        match &mut browser {
            BrowserHandle::Native(b) => b.stop(),
            BrowserHandle::Fallback(b) => b.stop(),
        }
        true
    } else {
        false
    }
}

/// Advertise a service
#[neon::export]
fn advertise_service<'cx>(
    cx: &mut FunctionContext<'cx>,
    name: String,
    service_type: String,
    port: f64,
    txt: Option<Handle<'cx, JsObject>>,
    callback: Handle<'cx, JsFunction>,
) -> NeonResult<Handle<'cx, JsNumber>> {
    let port = port as u16;
    let channel = cx.channel();
    let callback = std::sync::Arc::new(callback.root(cx));
    
    // Extract TXT record
    let txt_map: Option<HashMap<String, String>> = if let Some(txt_obj) = txt {
        let keys = txt_obj.get_own_property_names(cx)?;
        let len = keys.len(cx);
        let mut map = HashMap::new();
        for i in 0..len {
            let key: Handle<JsString> = keys.get(cx, i)?;
            let key_str = key.value(cx);
            let val: Handle<JsString> = txt_obj.get(cx, key_str.as_str())?;
            map.insert(key_str, val.value(cx));
        }
        Some(map)
    } else {
        None
    };
    
    let handle_id = next_handle();
    
    // Create callback wrapper
    let make_callback = |channel: neon::event::Channel, callback: std::sync::Arc<neon::handle::Root<JsFunction>>| {
        move |event: &str, data: &str| {
            let event = event.to_string();
            let data = data.to_string();
            let callback = callback.clone();
            
            channel.send(move |mut cx| {
                let cb = callback.to_inner(&mut cx);
                let this = cx.undefined();
                let event_val = cx.string(&event);
                let data_val = cx.string(&data);
                let _ = cb.call(&mut cx, this, vec![event_val.upcast(), data_val.upcast()]);
                Ok(())
            });
        }
    };

    let result = match get_backend() {
        Backend::Native => {
            native::NativeAdvertisement::new(
                &name,
                &service_type,
                port,
                txt_map.as_ref(),
                make_callback(channel, callback),
            ).map(AdvertisementHandle::Native)
        }
        Backend::Fallback => {
            fallback::FallbackAdvertisement::new(
                &name,
                &service_type,
                port,
                txt_map.as_ref(),
                make_callback(channel, callback),
            ).map(AdvertisementHandle::Fallback)
        }
    };
    
    match result {
        Ok(ad) => {
            ADVERTISEMENTS.lock().unwrap().insert(handle_id, ad);
            Ok(cx.number(handle_id as f64))
        }
        Err(e) => cx.throw_error(e),
    }
}

/// Stop advertising
#[neon::export]
fn stop_advertise(handle_id: f64) -> bool {
    let handle_id = handle_id as u32;
    if let Some(mut ad) = ADVERTISEMENTS.lock().unwrap().remove(&handle_id) {
        match &mut ad {
            AdvertisementHandle::Native(a) => a.stop(),
            AdvertisementHandle::Fallback(a) => a.stop(),
        }
        true
    } else {
        false
    }
}
