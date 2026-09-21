//! Cross-platform DNS-SD with dynamic backend selection
//! 
//! Tries native backend (Avahi/Bonjour) first, falls back to mdns-sd if unavailable.

mod ffi;
mod native;
mod fallback;

use neon::event::Channel;
use neon::prelude::*;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

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

/// A live handle plus the channel its callbacks are delivered on.
///
/// The channel is shared (rather than cloned) so there is exactly one reference
/// on the Node event loop per handle, and `set_*_ref` can drop or restore it.
struct Entry<H> {
    handle: H,
    channel: Arc<Mutex<Channel>>,
}

static BROWSERS: Lazy<Mutex<HashMap<u32, Entry<BrowserHandle>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Advertisement handles storage
enum AdvertisementHandle {
    Native(native::NativeAdvertisement),
    Fallback(fallback::FallbackAdvertisement),
}

static ADVERTISEMENTS: Lazy<Mutex<HashMap<u32, Entry<AdvertisementHandle>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Longest a single DNS label may be, in bytes (RFC 1035 section 2.3.4).
///
/// This is enforced here rather than left to the backends: Avahi and Bonjour
/// reject an over-long label with an opaque error code, and mdns-sd panics its
/// responder thread when it writes the packet, which silently kills an
/// advertisement the caller was already told had registered.
pub(crate) const MAX_LABEL_BYTES: usize = 63;

fn check_label(kind: &str, label: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err(format!("{} must not be empty", kind));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(format!(
            "{} is {} bytes, over the {} byte DNS label limit \
             (non-ASCII characters take more than one byte each)",
            kind,
            label.len(),
            MAX_LABEL_BYTES
        ));
    }
    Ok(())
}

/// Validate a service type such as `_http._tcp`, with optional `,subtype` suffixes.
fn check_service_type(service_type: &str) -> Result<(), String> {
    let (base, subtypes) = match service_type.split_once(',') {
        Some((base, subs)) => (base, Some(subs)),
        None => (service_type, None),
    };

    // Accept the fully qualified spellings too: "_http._tcp.local."
    let base = base.trim_end_matches('.');
    let base = base.strip_suffix(".local").unwrap_or(base);

    let labels: Vec<&str> = base.split('.').collect();
    let proto = labels.last().copied().unwrap_or("");
    if labels.len() < 2
        || !labels[0].starts_with('_')
        || !(proto.eq_ignore_ascii_case("_tcp") || proto.eq_ignore_ascii_case("_udp"))
    {
        return Err(format!(
            "service type must look like '_http._tcp' or '_http._udp', got '{}'",
            service_type
        ));
    }
    for label in &labels {
        check_label("service type label", label)?;
    }
    if let Some(subs) = subtypes {
        for sub in subs.split(',') {
            check_label("service subtype", sub)?;
        }
    }
    Ok(())
}

/// Validate a host name, label by label.
fn check_host_name(host: &str) -> Result<(), String> {
    for label in host.trim_end_matches('.').split('.') {
        check_label("host name label", label)?;
    }
    Ok(())
}

/// Normalize a caller supplied DNS-SD domain to its fully qualified form.
fn normalize_domain(domain: &str) -> String {
    let trimmed = domain.trim();
    if trimmed.ends_with('.') {
        trimmed.to_string()
    } else {
        format!("{}.", trimmed)
    }
}

/// Whether a domain is the mDNS link-local domain, the only one RFC 6762 defines.
fn is_local_domain(domain: Option<&String>) -> bool {
    match domain {
        None => true,
        Some(d) => d.eq_ignore_ascii_case("local."),
    }
}

/// Qualify a caller supplied SRV target host into the `.local.` domain.
///
/// Avahi's compat layer rejects a bare label with kDNSServiceErr_BadParam while
/// Bonjour accepts it, so every backend is handed the same fully qualified form.
fn qualify_host(host: &str) -> String {
    if host.ends_with('.') {
        host.to_string()
    } else if host.ends_with(".local") {
        format!("{}.", host)
    } else {
        format!("{}.local.", host)
    }
}

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
    domain: Option<String>,
    callback: Handle<'cx, JsFunction>,
) -> NeonResult<Handle<'cx, JsNumber>> {
    if let Err(e) = check_service_type(&service_type) {
        return cx.throw_error(e);
    }
    let domain = domain
        .filter(|d| !d.trim().is_empty())
        .map(|d| normalize_domain(&d));
    if let Some(d) = domain.as_deref() {
        if let Err(e) = check_host_name(d) {
            return cx.throw_error(e);
        }
    }
    let channel = Arc::new(Mutex::new(cx.channel()));
    let callback = std::sync::Arc::new(callback.root(cx));

    let handle_id = next_handle();

    // Create callback wrapper
    let make_callback = |channel: Arc<Mutex<Channel>>, callback: std::sync::Arc<neon::handle::Root<JsFunction>>| {
        move |event: &str, info: ServiceInfo| {
            let event = event.to_string();
            let callback = callback.clone();

            channel.lock().unwrap().send(move |mut cx| {
                let cb = callback.to_inner(&mut cx);
                let this = cx.undefined();
                let event_val = cx.string(&event);
                // Error events carry their message in `name`; the JS layer expects a string.
                let payload: Handle<JsValue> = if event == "error" {
                    cx.string(&info.name).upcast()
                } else {
                    service_info_to_js(&mut cx, &info)?.upcast()
                };
                let _ = cb.call(&mut cx, this, vec![event_val.upcast(), payload]);
                Ok(())
            });
        }
    };

    // The daemon can die between the availability probe and this call, so a
    // native failure degrades to the fallback rather than surfacing an error
    // the fallback could have handled.
    let native_result = match get_backend() {
        Backend::Native => Some(
            native::NativeBrowser::new(
                &service_type,
                domain.as_deref(),
                make_callback(channel.clone(), callback.clone()),
            )
            .map(BrowserHandle::Native),
        ),
        Backend::Fallback => None,
    };

    let native_error = match native_result {
        Some(Ok(handle)) => {
            BROWSERS
                .lock()
                .unwrap()
                .insert(handle_id, Entry { handle, channel });
            return Ok(cx.number(handle_id as f64));
        }
        Some(Err(e)) => {
            // Only a daemon that has gone away justifies switching backends;
            // a genuine failure (a name that stays in conflict, say) is the
            // caller's to see.
            native::invalidate_availability();
            if native::is_available() {
                return cx.throw_error(e);
            }
            Some(e)
        }
        None => None,
    };

    let result = match native_error {
        Some(e) if !is_local_domain(domain.as_ref()) => Err(e),
        _ => {
            if !is_local_domain(domain.as_ref()) {
                return cx.throw_error(format!(
                    "the mdns-sd fallback backend only serves the 'local' domain (RFC 6762); \
                     browsing '{}' needs a system DNS-SD daemon (Avahi or Bonjour)",
                    domain.unwrap_or_default()
                ));
            }
            // Convert fallback::ServiceInfo to our ServiceInfo
            let cb = make_callback(channel.clone(), callback);
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
        Ok(handle) => {
            BROWSERS
                .lock()
                .unwrap()
                .insert(handle_id, Entry { handle, channel });
            Ok(cx.number(handle_id as f64))
        }
        Err(e) => cx.throw_error(e),
    }
}

/// Stop browsing
#[neon::export]
fn stop_browse(handle_id: f64) -> bool {
    let handle_id = handle_id as u32;
    if let Some(mut entry) = BROWSERS.lock().unwrap().remove(&handle_id) {
        match &mut entry.handle {
            BrowserHandle::Native(b) => b.stop(),
            BrowserHandle::Fallback(b) => b.stop(),
        }
        true
    } else {
        false
    }
}

/// Keep the Node event loop alive for this browser, or let it exit.
#[neon::export]
fn set_browse_ref(cx: &mut FunctionContext, handle_id: f64, referenced: bool) -> bool {
    let handle_id = handle_id as u32;
    let map = BROWSERS.lock().unwrap();
    match map.get(&handle_id) {
        Some(entry) => {
            let mut channel = entry.channel.lock().unwrap();
            if referenced {
                channel.reference(cx);
            } else {
                channel.unref(cx);
            }
            true
        }
        None => false,
    }
}

/// Advertise a service
#[neon::export]
fn advertise_service<'cx>(
    cx: &mut FunctionContext<'cx>,
    name: String,
    service_type: String,
    domain: Option<String>,
    host_name: Option<String>,
    port: f64,
    txt: Option<Handle<'cx, JsObject>>,
    callback: Handle<'cx, JsFunction>,
) -> NeonResult<Handle<'cx, JsNumber>> {
    if let Err(e) = check_label("service name", &name) {
        return cx.throw_error(e);
    }
    if let Err(e) = check_service_type(&service_type) {
        return cx.throw_error(e);
    }
    if let Some(h) = host_name.as_deref().filter(|h| !h.is_empty()) {
        if let Err(e) = check_host_name(h) {
            return cx.throw_error(e);
        }
    }
    if let Some(d) = domain.as_deref().filter(|d| !d.trim().is_empty()) {
        if let Err(e) = check_host_name(d) {
            return cx.throw_error(e);
        }
    }
    if !port.is_finite() || port.fract() != 0.0 || !(0.0..=65535.0).contains(&port) {
        return cx.throw_error(format!(
            "port must be an integer between 0 and 65535, got {}",
            port
        ));
    }
    let port = port as u16;
    let host_name = host_name
        .filter(|h| !h.is_empty())
        .map(|h| qualify_host(&h));
    let domain = domain
        .filter(|d| !d.trim().is_empty())
        .map(|d| normalize_domain(&d));
    let channel = Arc::new(Mutex::new(cx.channel()));
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
        // RFC 6763 section 6.1: each "key=value" entry is length prefixed by a
        // single byte, so an oversized entry cannot be represented at all - and
        // a NUL byte would be truncated by the C string conversion downstream.
        for (k, v) in &map {
            if k.is_empty() {
                return cx.throw_error("TXT record keys must not be empty");
            }
            if k.as_bytes().contains(&0) || v.as_bytes().contains(&0) {
                return cx.throw_error(format!(
                    "TXT record entry '{}' must not contain NUL bytes",
                    k.escape_debug()
                ));
            }
            if k.len() + 1 + v.len() > 255 {
                return cx.throw_error(format!(
                    "TXT record entry '{}' is {} bytes, over the 255 byte DNS-SD limit",
                    k,
                    k.len() + 1 + v.len()
                ));
            }
        }
        Some(map)
    } else {
        None
    };
    
    let handle_id = next_handle();
    
    // Create callback wrapper
    let make_callback = |channel: Arc<Mutex<Channel>>, callback: std::sync::Arc<neon::handle::Root<JsFunction>>| {
        move |event: &str, data: &str| {
            let event = event.to_string();
            let data = data.to_string();
            let callback = callback.clone();

            channel.lock().unwrap().send(move |mut cx| {
                let cb = callback.to_inner(&mut cx);
                let this = cx.undefined();
                let event_val = cx.string(&event);
                let data_val = cx.string(&data);
                let _ = cb.call(&mut cx, this, vec![event_val.upcast(), data_val.upcast()]);
                Ok(())
            });
        }
    };

    // As with browsing: a native failure here means the daemon went away after
    // the availability probe, so degrade instead of failing outright.
    let native_result = match get_backend() {
        Backend::Native => Some(
            native::NativeAdvertisement::new(
                &name,
                &service_type,
                domain.as_deref(),
                host_name.as_deref(),
                port,
                txt_map.as_ref(),
                make_callback(channel.clone(), callback.clone()),
            )
            .map(AdvertisementHandle::Native),
        ),
        Backend::Fallback => None,
    };

    let native_error = match native_result {
        Some(Ok(handle)) => {
            ADVERTISEMENTS
                .lock()
                .unwrap()
                .insert(handle_id, Entry { handle, channel });
            return Ok(cx.number(handle_id as f64));
        }
        Some(Err(e)) => {
            // See the note in browse_services: degrade only when the daemon is
            // actually gone, not on every native failure.
            native::invalidate_availability();
            if native::is_available() {
                return cx.throw_error(e);
            }
            Some(e)
        }
        None => None,
    };

    let result = match native_error {
        Some(e) if !is_local_domain(domain.as_ref()) => Err(e),
        _ => {
            if !is_local_domain(domain.as_ref()) {
                return cx.throw_error(format!(
                    "the mdns-sd fallback backend only serves the 'local' domain (RFC 6762); \
                     advertising in '{}' needs a system DNS-SD daemon (Avahi or Bonjour) and \
                     DNS Update on that domain's server",
                    domain.unwrap_or_default()
                ));
            }
            fallback::FallbackAdvertisement::new(
                &name,
                &service_type,
                host_name.as_deref(),
                port,
                txt_map.as_ref(),
                make_callback(channel.clone(), callback),
            ).map(AdvertisementHandle::Fallback)
        }
    };
    
    match result {
        Ok(handle) => {
            ADVERTISEMENTS
                .lock()
                .unwrap()
                .insert(handle_id, Entry { handle, channel });
            Ok(cx.number(handle_id as f64))
        }
        Err(e) => cx.throw_error(e),
    }
}

/// Stop advertising
#[neon::export]
fn stop_advertise(handle_id: f64) -> bool {
    let handle_id = handle_id as u32;
    if let Some(mut entry) = ADVERTISEMENTS.lock().unwrap().remove(&handle_id) {
        match &mut entry.handle {
            AdvertisementHandle::Native(a) => a.stop(),
            AdvertisementHandle::Fallback(a) => a.stop(),
        }
        true
    } else {
        false
    }
}

/// Keep the Node event loop alive for this advertisement, or let it exit.
#[neon::export]
fn set_advertise_ref(cx: &mut FunctionContext, handle_id: f64, referenced: bool) -> bool {
    let handle_id = handle_id as u32;
    let map = ADVERTISEMENTS.lock().unwrap();
    match map.get(&handle_id) {
        Some(entry) => {
            let mut channel = entry.channel.lock().unwrap();
            if referenced {
                channel.reference(cx);
            } else {
                channel.unref(cx);
            }
            true
        }
        None => false,
    }
}
