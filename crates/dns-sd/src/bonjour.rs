//! Native DNS-SD backend using libloading to dynamically load dns_sd library

use crate::ffi::*;
use libloading::Library;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ----------------------------------------------------------------
// Cross-platform compat layer
// ----------------------------------------------------------------

#[cfg(unix)]
mod sys {
    pub use libc::{AF_INET, AF_INET6, sockaddr_in, sockaddr_in6, poll, pollfd, POLLIN};
}

#[cfg(windows)]
mod sys {
    #![allow(non_camel_case_types)]
    
    // We need to define compatible types because libc on Windows
    // doesn't expose them in the top-level or possibly at all in the same way.
    // However, for FFI with generic C APIs, we need layouts matching C.
    
    pub type sa_family_t = u16;
    
    pub const AF_INET: u16 = 2;
    pub const AF_INET6: u16 = 23;

    #[repr(C)]
    pub struct in_addr {
        pub s_addr: u32,
    }

    #[repr(C)]
    pub struct sockaddr_in {
        pub sin_family: sa_family_t,
        pub sin_port: u16,
        pub sin_addr: in_addr,
        pub sin_zero: [u8; 8],
    }

    #[repr(C)]
    pub struct in6_addr {
        pub s6_addr: [u8; 16],
    }

    #[repr(C)]
    pub struct sockaddr_in6 {
        pub sin6_family: sa_family_t,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: in6_addr,
        pub sin6_scope_id: u32,
    }

    // POLL structs
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct pollfd {
        pub fd: i64, // SOCKET is u64/usize usually, but on Windows 64-bit it is 64-bit
                     // BUT, dns_sd uses int for FD usually? 
                     // Wait, DNSServiceRefSockFD returns int.
                     // On Windows, it might return a SOCKET cast to int?
                     // Or maybe we treat it as raw handle.
        pub events: i16,
        pub revents: i16,
    }

    pub const POLLIN: i16 = 0x0100; // 0x0300 is RDNORM | RDBAND usually, but let's check WSAPoll.
                                    // WSAPoll defaults:
                                    // POLLIN = 0x0100 | 0x0200 (RDNORM | RDBAND)
                                    // Actually, standard is:
                                    // #define POLLIN 0x0300
    
    // Let's use standard values compatible with WSAPoll
    // Win32:
    // POLLIN = 0x0300
    // But let's check what libc expects if we were using it.
    // We will just use what WSAPoll expects.
    
    // However, since we can't link ws2_32 easily safely in this simple patch without build.rs changes?
    // Actually, we can use libloading for WSAPoll too!
    
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAPoll(fdArray: *mut pollfd, fds: u32, timeout: i32) -> i32;
    }

    pub unsafe fn poll(fds: *mut pollfd, nfds: u64, timeout: i32) -> i32 {
         unsafe { WSAPoll(fds, nfds as u32, timeout) }
    }
}


/// How many names to try when resolving a conflict, per RFC 6762 section 9.
const MAX_NAME_ATTEMPTS: u32 = 10;

/// How long to wait for a service's addresses before giving up
const ADDRESS_TIMEOUT_MS: u128 = 2000;
/// How long the address set must stay unchanged before it counts as complete
const ADDRESS_SETTLE: Duration = Duration::from_millis(300);

/// Global library instance
static LIBRARY: OnceCell<Result<DnsSdLibrary, String>> = OnceCell::new();

/// Loaded DNS-SD library with function pointers
pub struct DnsSdLibrary {
    _lib: Library,
    pub browse: FnDNSServiceBrowse,
    pub resolve: FnDNSServiceResolve,
    pub register: FnDNSServiceRegister,
    pub get_addr_info: Option<FnDNSServiceGetAddrInfo>,
    pub create_connection: Option<FnDNSServiceCreateConnection>,
    pub query_record: FnDNSServiceQueryRecord,
    pub ref_sock_fd: FnDNSServiceRefSockFD,
    pub process_result: FnDNSServiceProcessResult,
    pub ref_deallocate: FnDNSServiceRefDeallocate,
    pub txt_record_create: FnTXTRecordCreate,
    pub txt_record_deallocate: FnTXTRecordDeallocate,
    pub txt_record_set_value: FnTXTRecordSetValue,
    pub txt_record_get_length: FnTXTRecordGetLength,
    pub txt_record_get_bytes_ptr: FnTXTRecordGetBytesPtr,
}

// SAFETY: The library functions are thread-safe according to DNS-SD spec
unsafe impl Send for DnsSdLibrary {}
unsafe impl Sync for DnsSdLibrary {}

impl DnsSdLibrary {
    /// Try to load the DNS-SD library
    pub fn load() -> Result<Self, String> {
        let lib_path = get_library_path();
        
        // SAFETY: Loading external library
        let lib = unsafe { Library::new(lib_path) }
            .map_err(|e| format!("Failed to load {}: {}", lib_path, e))?;

        // SAFETY: Loading symbols from library
        unsafe {
            let browse = *lib.get::<FnDNSServiceBrowse>(b"DNSServiceBrowse\0")
                .map_err(|e| format!("DNSServiceBrowse: {}", e))?;
            let resolve = *lib.get::<FnDNSServiceResolve>(b"DNSServiceResolve\0")
                .map_err(|e| format!("DNSServiceResolve: {}", e))?;
            let register = *lib.get::<FnDNSServiceRegister>(b"DNSServiceRegister\0")
                .map_err(|e| format!("DNSServiceRegister: {}", e))?;
            
            // Optional symbol - might be missing on Linux Avahi compat
            let get_addr_info = lib.get::<FnDNSServiceGetAddrInfo>(b"DNSServiceGetAddrInfo\0")
                .ok()
                .map(|sym| *sym);

            // Used to check that a daemon is actually listening, not just that
            // the library linked.
            let create_connection = lib
                .get::<FnDNSServiceCreateConnection>(b"DNSServiceCreateConnection\0")
                .ok()
                .map(|sym| *sym);

            let query_record = *lib.get::<FnDNSServiceQueryRecord>(b"DNSServiceQueryRecord\0")
                .map_err(|e| format!("DNSServiceQueryRecord: {}", e))?;

            let ref_sock_fd = *lib.get::<FnDNSServiceRefSockFD>(b"DNSServiceRefSockFD\0")
                .map_err(|e| format!("DNSServiceRefSockFD: {}", e))?;
            let process_result = *lib.get::<FnDNSServiceProcessResult>(b"DNSServiceProcessResult\0")
                .map_err(|e| format!("DNSServiceProcessResult: {}", e))?;
            let ref_deallocate = *lib.get::<FnDNSServiceRefDeallocate>(b"DNSServiceRefDeallocate\0")
                .map_err(|e| format!("DNSServiceRefDeallocate: {}", e))?;
            let txt_record_create = *lib.get::<FnTXTRecordCreate>(b"TXTRecordCreate\0")
                .map_err(|e| format!("TXTRecordCreate: {}", e))?;
            let txt_record_deallocate = *lib.get::<FnTXTRecordDeallocate>(b"TXTRecordDeallocate\0")
                .map_err(|e| format!("TXTRecordDeallocate: {}", e))?;
            let txt_record_set_value = *lib.get::<FnTXTRecordSetValue>(b"TXTRecordSetValue\0")
                .map_err(|e| format!("TXTRecordSetValue: {}", e))?;
            let txt_record_get_length = *lib.get::<FnTXTRecordGetLength>(b"TXTRecordGetLength\0")
                .map_err(|e| format!("TXTRecordGetLength: {}", e))?;
            let txt_record_get_bytes_ptr = *lib.get::<FnTXTRecordGetBytesPtr>(b"TXTRecordGetBytesPtr\0")
                .map_err(|e| format!("TXTRecordGetBytesPtr: {}", e))?;

            Ok(DnsSdLibrary {
                _lib: lib,
                browse,
                resolve,
                register,
                get_addr_info,
                create_connection,
                query_record,
                ref_sock_fd,
                process_result,
                ref_deallocate,
                txt_record_create,
                txt_record_deallocate,
                txt_record_set_value,
                txt_record_get_length,
                txt_record_get_bytes_ptr,
            })
        }
    }
    
    /// Get or initialize the global library instance
    pub fn get() -> Result<&'static DnsSdLibrary, String> {
        LIBRARY
            .get_or_init(|| DnsSdLibrary::load())
            .as_ref()
            .map_err(|e| e.clone())
    }
}

/// Check if native backend is available
/// Cached daemon probe result. Cleared as soon as anything observes the daemon
/// failing, so a caller recreating a handle after an error is never handed a
/// stale "the daemon is fine" answer.
static AVAILABILITY_CACHE: Mutex<Option<(std::time::Instant, bool)>> = Mutex::new(None);

/// Forget the cached probe result.
pub fn invalidate_availability() {
    *AVAILABILITY_CACHE.lock().unwrap() = None;
}

/// Counterpart to avahi.rs's check of the same name; never blocks here.
/// macOS/Windows ship the DNS-SD library and the responder together, so
/// failing to load one means the other isn't there to collide with.
pub fn fallback_publish_conflict() -> Option<String> {
    None
}

pub fn is_available() -> bool {
    // Probing costs a round trip to the daemon, and handles are often created
    // in bursts, so the answer is reused briefly.
    const CACHE_TTL: Duration = Duration::from_secs(5);

    let mut cache = AVAILABILITY_CACHE.lock().unwrap();
    if let Some((checked_at, available)) = *cache {
        if checked_at.elapsed() < CACHE_TTL {
            return available;
        }
    }

    let available = probe_daemon();
    *cache = Some((std::time::Instant::now(), available));
    available
}

/// Check that a DNS-SD daemon is actually reachable.
///
/// Linking is not the same as being usable: Avahi's compat library loads
/// happily while avahi-daemon is not running, and every call then fails. This
/// is what lets the mdns-sd fallback take over when the system service is
/// unavailable, rather than only when the library is missing.
fn probe_daemon() -> bool {
    let lib = match DnsSdLibrary::get() {
        Ok(lib) => lib,
        Err(_) => return false,
    };

    // Bonjour answers this without touching the network.
    if let Some(create_connection) = lib.create_connection {
        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        let err = unsafe { create_connection(&mut sd_ref) };
        if err == K_DNS_SERVICE_ERR_NO_ERROR {
            if !sd_ref.is_null() {
                unsafe { (lib.ref_deallocate)(sd_ref) };
            }
            return true;
        }
        if err != K_DNS_SERVICE_ERR_UNSUPPORTED {
            return false;
        }
    }

    // Starting a browse fails immediately when no daemon is listening. It is
    // torn down before it can produce any traffic of consequence.
    let probe_type = match CString::new("_dns-sd-probe._udp") {
        Ok(t) => t,
        Err(_) => return false,
    };
    let mut sd_ref: DNSServiceRef = ptr::null_mut();
    let err = unsafe {
        (lib.browse)(
            &mut sd_ref,
            0,
            0,
            probe_type.as_ptr(),
            ptr::null(),
            None,
            ptr::null_mut(),
        )
    };
    if err == K_DNS_SERVICE_ERR_NO_ERROR && !sd_ref.is_null() {
        unsafe { (lib.ref_deallocate)(sd_ref) };
        true
    } else {
        false
    }
}

/// Service info from browse/resolve
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub service_type: String,
    pub domain: String,
    pub host_name: String,
    pub addresses: Vec<String>,
    pub port: u16,
    pub txt: HashMap<String, String>,
    pub ttl: u32,
}

impl ServiceInfo {
    /// Carrier for an error message on the browse callback channel.
    ///
    /// `lib.rs` hands the JS side `name` as a plain string when the event is
    /// `"error"`, so browse failures surface as an `'error'` event instead of
    /// being swallowed.
    pub fn error(message: String) -> Self {
        ServiceInfo {
            name: message,
            service_type: String::new(),
            domain: String::new(),
            host_name: String::new(),
            addresses: vec![],
            port: 0,
            txt: HashMap::new(),
            ttl: 0,
        }
    }
}

/// Shared callback type for thread-safe access
type SharedCallback = Arc<dyn Fn(&str, ServiceInfo) + Send + Sync + 'static>;

/// Context passed to browse callback
struct BrowseContext {
    callback: SharedCallback,
    /// Set once the daemon reports a failure. dns_sd.h states that an error
    /// delivered to a callback means the operation has failed for good, so the
    /// poll thread stops instead of idling on a handle that can never produce
    /// another event.
    dead: Arc<AtomicBool>,
}

/// Browse callback - spawns resolve thread for each service
unsafe extern "C" fn browse_callback(
    _sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32_t,
    error_code: DNSServiceErrorType,
    service_name: *const libc::c_char,
    reg_type: *const libc::c_char,
    reply_domain: *const libc::c_char,
    context: *mut c_void,
) {
    unsafe {
        let ctx = &*(context as *const BrowseContext);

        if error_code != K_DNS_SERVICE_ERR_NO_ERROR {
            (ctx.callback)("error", ServiceInfo::error(error_message(error_code)));
            ctx.dead.store(true, Ordering::SeqCst);
            invalidate_availability();
            return;
        }

        
        let name = CStr::from_ptr(service_name).to_string_lossy().into_owned();
        let service_type = CStr::from_ptr(reg_type).to_string_lossy().into_owned();
        let domain = CStr::from_ptr(reply_domain).to_string_lossy().into_owned();

        let is_add = (flags & K_DNS_SERVICE_FLAGS_ADD) != 0;

        if is_add {
            // Spawn thread for async resolve
            let callback = ctx.callback.clone();
            thread::spawn(move || {
                resolve_service_full(interface_index, &name, &service_type, &domain, callback);
            });
        } else {
            // serviceLost - emit immediately
            let info = ServiceInfo {
                name,
                service_type,
                domain,
                host_name: String::new(),
                addresses: vec![],
                port: 0,
                txt: HashMap::new(),
                ttl: 0,
            };
            (ctx.callback)("serviceLost", info);
        }
    }
}


/// Shared state for resolution process
struct ResolveState {
    info: ServiceInfo,
    /// When the last field/address update landed - used to stop polling early
    /// once a service has settled instead of always burning the full timeout.
    last_update: std::time::Instant,
}

/// Fully resolve a service - gets hostname, port, TXT, and IP addresses
fn resolve_service_full(
    interface_index: u32_t,
    name: &str,
    service_type: &str,
    domain: &str,
    callback: SharedCallback,
) {
    let lib = match DnsSdLibrary::get() {
        Ok(lib) => lib,
        Err(_) => return,
    };

    let name_c = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return,
    };
    let type_c = match CString::new(service_type) {
        Ok(s) => s,
        Err(_) => return,
    };
    let domain_c = match CString::new(domain) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Shared state
    let state = Arc::new(Mutex::new(ResolveState {
        last_update: std::time::Instant::now(),
        info: ServiceInfo {
            name: name.to_string(),
            service_type: service_type.to_string(),
            domain: domain.to_string(),
            host_name: String::new(),
            addresses: vec![],
            port: 0,
            txt: HashMap::new(),
            ttl: 0,
        },
    }));
    let state_resolve = state.clone();

    // Step 1: DNSServiceResolve to get hostname, port, TXT
    unsafe extern "C" fn resolve_cb(
        _sd_ref: DNSServiceRef,
        _flags: DNSServiceFlags,
        _interface_index: u32_t,
        error_code: DNSServiceErrorType,
        _fullname: *const libc::c_char,
        hosttarget: *const libc::c_char,
        port: libc::c_ushort,
        txt_len: libc::c_ushort,
        txt_record: *const libc::c_char,
        context: *mut c_void,
    ) {
        if error_code != K_DNS_SERVICE_ERR_NO_ERROR {
            return;
        }

        let (mut state, callback) = unsafe {
             let ctx = &*(context as *const (Arc<Mutex<ResolveState>>, SharedCallback));
             (ctx.0.lock().unwrap(), ctx.1.clone())
        };
        
        unsafe {
            state.info.host_name = CStr::from_ptr(hosttarget).to_string_lossy().into_owned();
            state.info.port = u16::from_be(port);
            state.info.txt = parse_txt_record(txt_record as *const u8, txt_len as usize);
        }
        state.last_update = std::time::Instant::now();

        // Emit partial result
        callback("serviceFound", state.info.clone());
    }

    let mut resolve_ref: DNSServiceRef = ptr::null_mut();
    // Bundle context
    let resolve_ctx = (state.clone(), callback.clone());
    
    let err = unsafe {
        (lib.resolve)(
            &mut resolve_ref,
            0,
            interface_index,
            name_c.as_ptr(),
            type_c.as_ptr(),
            domain_c.as_ptr(),
            Some(resolve_cb),
            &resolve_ctx as *const _ as *mut c_void,
        )
    };

    if err != K_DNS_SERVICE_ERR_NO_ERROR || resolve_ref.is_null() {
        return;
    }

    // Poll until we get hostname (short timeout)
    poll_service_refs(lib, &[resolve_ref], 3000, || {
        let s = state_resolve.lock().unwrap();
        !s.info.host_name.is_empty()
    });
    
    unsafe {
        (lib.ref_deallocate)(resolve_ref);
    }

    // Check if we got host
    let current_info = {
         let s = state.lock().unwrap();
         if s.info.host_name.is_empty() {
             return; // Failed to resolve host
         }
         s.info.clone()
    };

    // Step 2: Resolve IPs
    // Try DNSServiceGetAddrInfo first (standard DNS-SD way)
    if let Some(get_addr_info) = lib.get_addr_info {
        let host_c = match CString::new(current_info.host_name.as_str()) {
            Ok(s) => s,
            Err(_) => return,
        };



        unsafe extern "C" fn addr_cb(
            _sd_ref: DNSServiceRef,
            _flags: DNSServiceFlags,
            _interface_index: u32_t,
            error_code: DNSServiceErrorType,
            _hostname: *const libc::c_char,
            address: *const libc::sockaddr,
            ttl: u32_t,
            context: *mut c_void,
        ) {
            if error_code != K_DNS_SERVICE_ERR_NO_ERROR || address.is_null() {
                 return;
            }

            let (mut state, callback) = unsafe {
                 let ctx = &*(context as *const (Arc<Mutex<ResolveState>>, SharedCallback));
                 (ctx.0.lock().unwrap(), ctx.1.clone())
            };
            
            state.info.ttl = ttl;

            unsafe {
                let sa_family = (*address).sa_family;
                let mut ip_str = String::new();

                if u16::from(sa_family) == sys::AF_INET as u16 {
                    let addr4 = address as *const sys::sockaddr_in;
                    let ip_bytes = (*addr4).sin_addr.s_addr.to_ne_bytes();
                    let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                    ip_str = IpAddr::V4(ip).to_string();
                } else if u16::from(sa_family) == sys::AF_INET6 as u16 {
                    let addr6 = address as *const sys::sockaddr_in6;
                    let ip_bytes = (*addr6).sin6_addr.s6_addr;
                    let ip = Ipv6Addr::from(ip_bytes);
                    ip_str = IpAddr::V6(ip).to_string();
                }

                if !ip_str.is_empty() && !state.info.addresses.contains(&ip_str) {
                    state.info.addresses.push(ip_str);
                    state.last_update = std::time::Instant::now();
                    // Emit update for each new address
                    callback("serviceFound", state.info.clone());
                }
            }
        }

        let mut addr_ref: DNSServiceRef = ptr::null_mut();
        // Bundle context
        let addr_ctx = (state.clone(), callback.clone());

        let err = unsafe {
            (get_addr_info)(
                &mut addr_ref,
                0, // flags
                interface_index,
                0, // any protocol
                host_c.as_ptr(),
                Some(addr_cb),
                &addr_ctx as *const _ as *mut c_void,
            )
        };

        if err == K_DNS_SERVICE_ERR_NO_ERROR && !addr_ref.is_null() {
            let state_addr = state.clone();
            // Collect addresses until they stop arriving, capped at the timeout
            poll_service_refs(lib, &[addr_ref], ADDRESS_TIMEOUT_MS, || {
                let s = state_addr.lock().unwrap();
                !s.info.addresses.is_empty() && s.last_update.elapsed() >= ADDRESS_SETTLE
            });

            unsafe {
                (lib.ref_deallocate)(addr_ref);
            }
        }
    } else {
        // Fallback: Use DNSServiceQueryRecord for A and AAAA records (Avahi Compat)
        
        let host_c = match CString::new(current_info.host_name.as_str()) {
             Ok(s) => s,
             Err(_) => return,
        };

        unsafe extern "C" fn query_cb(
            _sd_ref: DNSServiceRef,
            _flags: DNSServiceFlags,
            _interface_index: u32_t,
            error_code: DNSServiceErrorType,
            _fullname: *const libc::c_char,
            rrtype: u16,
            _rrclass: u16,
            rdlen: u16,
            rdata: *const c_void,
            ttl: u32_t,
            context: *mut c_void,
        ) {
            if error_code != K_DNS_SERVICE_ERR_NO_ERROR || rdata.is_null() {
                return;
            }

            let (mut state, callback) = unsafe {
                 let ctx = &*(context as *const (Arc<Mutex<ResolveState>>, SharedCallback));
                 (ctx.0.lock().unwrap(), ctx.1.clone())
            };
            
            // Only update TTL if we have a valid one (take the larger one or just latest)
            if ttl > 0 {
                state.info.ttl = ttl;
            }

            let mut ip_str = String::new();
            if rrtype == K_DNS_SERVICE_TYPE_A && rdlen == 4 {
                let ip_bytes: &[u8; 4] = unsafe { &*(rdata as *const [u8; 4]) };
                let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                ip_str = IpAddr::V4(ip).to_string();
            } else if rrtype == K_DNS_SERVICE_TYPE_AAAA && rdlen == 16 {
                let ip_bytes: &[u8; 16] = unsafe { &*(rdata as *const [u8; 16]) };
                let ip = Ipv6Addr::from(*ip_bytes);
                ip_str = IpAddr::V6(ip).to_string();
            }

            if !ip_str.is_empty() && !state.info.addresses.contains(&ip_str) {
                state.info.addresses.push(ip_str);
                state.last_update = std::time::Instant::now();
                callback("serviceFound", state.info.clone());
            }
        }
        
        
        let cb_ctx = (state.clone(), callback.clone());
        let cb_ctx6 = (state.clone(), callback.clone()); // Context needs to stay alive

        let mut query_ref: DNSServiceRef = ptr::null_mut();
        let mut query_ref6: DNSServiceRef = ptr::null_mut();

        // 1. Query A Record
        let err_a = unsafe {
            (lib.query_record)(
                &mut query_ref,
                0,
                interface_index,
                host_c.as_ptr(),
                K_DNS_SERVICE_TYPE_A,
                1, // kDNSServiceClass_IN
                Some(query_cb),
                &cb_ctx as *const _ as *mut c_void,
            )
        };
        
        // 2. Query AAAA Record
        let err_aaaa = unsafe {
             (lib.query_record)(
                &mut query_ref6,
                0,
                interface_index,
                host_c.as_ptr(),
                K_DNS_SERVICE_TYPE_AAAA,
                1, // kDNSServiceClass_IN
                Some(query_cb),
                &cb_ctx6 as *const _ as *mut c_void,
             )
        };

        if (err_a == K_DNS_SERVICE_ERR_NO_ERROR && !query_ref.is_null()) || 
           (err_aaaa == K_DNS_SERVICE_ERR_NO_ERROR && !query_ref6.is_null()) {
             
            let state_query = state.clone();
            // Poll both refs together; stop once the address set has settled
            poll_service_refs(lib, &[query_ref, query_ref6], ADDRESS_TIMEOUT_MS, || {
                let s = state_query.lock().unwrap();
                !s.info.addresses.is_empty() && s.last_update.elapsed() >= ADDRESS_SETTLE
            });

            unsafe {
                if !query_ref.is_null() { (lib.ref_deallocate)(query_ref); }
                if !query_ref6.is_null() { (lib.ref_deallocate)(query_ref6); }
            }
        }
    }
}

/// Poll one or more service refs until the predicate passes or the timeout elapses.
///
/// Every ref is checked for readability before `DNSServiceProcessResult` is called:
/// that call blocks until a record arrives, so processing an idle ref would wedge
/// the loop, leak the thread and leave the refs deallocated forever.
fn poll_service_refs<F>(
    lib: &DnsSdLibrary,
    refs: &[DNSServiceRef],
    timeout_ms: u128,
    mut should_exit: F,
) where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let mut pfds: Vec<sys::pollfd> = Vec::with_capacity(refs.len());
    let mut active: Vec<DNSServiceRef> = Vec::with_capacity(refs.len());

    while start.elapsed().as_millis() < timeout_ms {
        if should_exit() {
            break;
        }

        pfds.clear();
        active.clear();

        for &sd_ref in refs {
            if sd_ref.is_null() {
                continue;
            }
            let fd = unsafe { (lib.ref_sock_fd)(sd_ref) };
            if fd < 0 {
                continue;
            }
            pfds.push(sys::pollfd {
                fd: fd as _,
                events: sys::POLLIN,
                revents: 0,
            });
            active.push(sd_ref);
        }

        if pfds.is_empty() {
            break;
        }

        let remaining = timeout_ms.saturating_sub(start.elapsed().as_millis()).max(1) as i32;
        let poll_timeout = remaining.min(100); // Poll in chunks so the predicate is re-checked

        let ready = unsafe { sys::poll(pfds.as_mut_ptr(), pfds.len() as _, poll_timeout) };
        if ready <= 0 {
            continue;
        }

        for (i, pfd) in pfds.iter().enumerate() {
            // Any reported event (including POLLERR/POLLHUP) is handed to the library,
            // which reports the failure through its own error code.
            if pfd.revents != 0 {
                unsafe {
                    (lib.process_result)(active[i]);
                }
            }
        }
    }
}


/// Parse TXT record bytes into key-value map
fn parse_txt_record(data: *const u8, len: usize) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if data.is_null() || len == 0 {
        return map;
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let mut i = 0;
    while i < bytes.len() {
        let entry_len = bytes[i] as usize;
        i += 1;
        if i + entry_len > bytes.len() {
            break;
        }
        let entry = &bytes[i..i + entry_len];
        i += entry_len;

        if let Some(eq_pos) = entry.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&entry[..eq_pos]).into_owned();
            let value = String::from_utf8_lossy(&entry[eq_pos + 1..]).into_owned();
            map.insert(key, value);
        } else {
            let key = String::from_utf8_lossy(entry).into_owned();
            map.insert(key, String::new());
        }
    }
    map
}

/// Browser handle for native backend
pub struct NativeBrowser {
    sd_ref: DNSServiceRef,
    stop_flag: Arc<Mutex<bool>>,
    thread: Option<thread::JoinHandle<()>>,
    _context: *mut BrowseContext,
    stopped: bool,
}

unsafe impl Send for NativeBrowser {}

impl NativeBrowser {
    /// Start browsing for services
    pub fn new<F>(service_type: &str, domain: Option<&str>, callback: F) -> Result<Self, String>
    where
        F: Fn(&str, ServiceInfo) + Send + Sync + 'static,
    {
        let lib = DnsSdLibrary::get()?;

        let reg_type = CString::new(service_type).map_err(|e| e.to_string())?;
        // NULL means "the daemon's default domains"
        let domain_c = match domain {
            Some(d) if !d.is_empty() => Some(CString::new(d).map_err(|e| e.to_string())?),
            _ => None,
        };
        let domain_ptr = domain_c.as_ref().map_or(ptr::null(), |d| d.as_ptr());

        let stop_flag = Arc::new(Mutex::new(false));

        let dead = Arc::new(AtomicBool::new(false));
        let ctx = Box::new(BrowseContext {
            callback: Arc::new(callback),
            dead: dead.clone(),
        });
        let ctx_ptr = Box::into_raw(ctx);
        
        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        
        let err = unsafe {
            (lib.browse)(
                &mut sd_ref,
                0,
                0,
                reg_type.as_ptr(),
                domain_ptr,
                Some(browse_callback),
                ctx_ptr as *mut c_void,
            )
        };

        if let Err(e) = check_error(err) {
            unsafe { drop(Box::from_raw(ctx_ptr)) };
            return Err(e);
        }

        if sd_ref.is_null() {
            unsafe { drop(Box::from_raw(ctx_ptr)) };
            return Err("DNSServiceBrowse returned null".into());
        }

        // Start event loop thread
        let sd_ref_copy = sd_ref as usize;
        let stop_flag_clone = stop_flag.clone();
        // SAFETY: ctx_ptr stays alive until stop() reclaims it, and stop() joins
        // this thread first.
        let thread_callback = unsafe { (*ctx_ptr).callback.clone() };
        let dead_clone = dead.clone();

        let thread = thread::spawn(move || {
            let sd_ref = sd_ref_copy as DNSServiceRef;
            let lib = match DnsSdLibrary::get() {
                Ok(lib) => lib,
                Err(_) => return,
            };

            loop {
                if *stop_flag_clone.lock().unwrap() || dead_clone.load(Ordering::SeqCst) {
                    break;
                }

                unsafe {
                    let fd = (lib.ref_sock_fd)(sd_ref);
                    if fd < 0 {
                        // The daemon went away: the browse is dead and no further
                        // events will ever arrive, so say so instead of going quiet.
                        thread_callback(
                            "error",
                            ServiceInfo::error(
                                "browse connection to the DNS-SD daemon was lost".to_string(),
                            ),
                        );
                        break;
                    }

                    let mut pfd = sys::pollfd {
                        fd: fd as _,
                        events: sys::POLLIN,
                        revents: 0,
                    };

                    let ready = sys::poll(&mut pfd, 1, 100);

                    if ready > 0 {
                        let err = (lib.process_result)(sd_ref);
                        if err != K_DNS_SERVICE_ERR_NO_ERROR {
                            thread_callback(
                                "error",
                                ServiceInfo::error(format!(
                                    "browse stopped: {}",
                                    error_message(err)
                                )),
                            );
                            break;
                        }
                    }
                }
            }
        });

        Ok(NativeBrowser {
            sd_ref,
            stop_flag,
            thread: Some(thread),
            _context: ctx_ptr,
            stopped: false,
        })
    }

    /// Stop browsing
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        
        *self.stop_flag.lock().unwrap() = true;
        
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }

        if !self.sd_ref.is_null() {
            if let Ok(lib) = DnsSdLibrary::get() {
                unsafe {
                    (lib.ref_deallocate)(self.sd_ref);
                }
            }
            self.sd_ref = ptr::null_mut();
        }

        if !self._context.is_null() {
            unsafe {
                let _ = Box::from_raw(self._context);
            }
            self._context = ptr::null_mut();
        }
    }
}

impl Drop for NativeBrowser {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Context for register callback
struct RegisterContext {
    callback: Arc<dyn Fn(&str, &str) + Send + Sync + 'static>,
    /// See `BrowseContext::dead`.
    dead: Arc<AtomicBool>,
}

/// Register callback
unsafe extern "C" fn register_callback(
    _sd_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    error_code: DNSServiceErrorType,
    name: *const libc::c_char,
    _reg_type: *const libc::c_char,
    _domain: *const libc::c_char,
    context: *mut c_void,
) {
    unsafe {
        let ctx = &*(context as *const RegisterContext);
        
        if error_code == K_DNS_SERVICE_ERR_NO_ERROR {
            let name_str = CStr::from_ptr(name).to_string_lossy().into_owned();
            (ctx.callback)("registered", &name_str);
        } else {
            (ctx.callback)("error", &error_message(error_code));
            ctx.dead.store(true, Ordering::SeqCst);
            invalidate_availability();
        }
    }
}

/// Advertisement handle for native backend
pub struct NativeAdvertisement {
    sd_ref: DNSServiceRef,
    stop_flag: Arc<Mutex<bool>>,
    thread: Option<thread::JoinHandle<()>>,
    _context: *mut RegisterContext,
    stopped: bool,
}

unsafe impl Send for NativeAdvertisement {}

impl NativeAdvertisement {
    /// Advertise a service
    pub fn new<F>(
        name: &str,
        service_type: &str,
        domain: Option<&str>,
        host_name: Option<&str>,
        port: u16,
        txt: Option<&HashMap<String, String>>,
        callback: F,
    ) -> Result<Self, String>
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        let lib = DnsSdLibrary::get()?;

        // Everything fallible runs before the context is leaked into C, so an
        // early return can never strand the allocation.
        let name_c = CString::new(name).map_err(|e| e.to_string())?;
        let reg_type = CString::new(service_type).map_err(|e| e.to_string())?;
        let host_c = match host_name {
            Some(h) if !h.is_empty() => Some(CString::new(h).map_err(|e| e.to_string())?),
            _ => None,
        };
        let host_ptr = host_c.as_ref().map_or(ptr::null(), |h| h.as_ptr());
        let domain_c = match domain {
            Some(d) if !d.is_empty() => Some(CString::new(d).map_err(|e| e.to_string())?),
            _ => None,
        };
        let domain_ptr = domain_c.as_ref().map_or(ptr::null(), |d| d.as_ptr());

        let mut txt_entries: Vec<(CString, &str)> = Vec::new();
        if let Some(txt_map) = txt {
            for (k, v) in txt_map {
                // RFC 6763 section 6.1: a whole "key=value" entry is length
                // prefixed by a single byte, so it cannot exceed 255 bytes.
                if k.len() + 1 + v.len() > 255 {
                    return Err(format!(
                        "TXT record entry '{}' is {} bytes, over the 255 byte DNS-SD limit",
                        k,
                        k.len() + 1 + v.len()
                    ));
                }
                let key_c = CString::new(k.as_str())
                    .map_err(|_| format!("TXT record key '{}' contains a NUL byte", k.escape_debug()))?;
                if v.as_bytes().contains(&0) {
                    return Err(format!("TXT record value for '{}' contains a NUL byte", k));
                }
                txt_entries.push((key_c, v.as_str()));
            }
        }

        let stop_flag = Arc::new(Mutex::new(false));

        let dead = Arc::new(AtomicBool::new(false));
        let ctx = Box::new(RegisterContext {
            callback: Arc::new(callback),
            dead: dead.clone(),
        });
        let ctx_ptr = Box::into_raw(ctx);

        // Build TXT record
        let mut txt_ref = TXTRecordRef::new();
        let (txt_len, txt_ptr) = if txt.is_some() {
            unsafe {
                (lib.txt_record_create)(&mut txt_ref, 0, ptr::null_mut());

                for (key_c, value) in &txt_entries {
                    let _ = (lib.txt_record_set_value)(
                        &mut txt_ref,
                        key_c.as_ptr(),
                        value.len() as u8,
                        value.as_ptr() as *const c_void,
                    );
                }

                let len = (lib.txt_record_get_length)(&txt_ref);
                let ptr = (lib.txt_record_get_bytes_ptr)(&txt_ref);
                (len, ptr)
            }
        } else {
            (0, ptr::null())
        };

        // RFC 6762 section 9 conflict resolution: Bonjour and the mdns-sd
        // responder rename a clashing service themselves ("Name (2)"), while
        // Avahi's compat layer just refuses with kDNSServiceErr_NameConflict.
        // Renaming here keeps every backend behaving the same.
        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        let mut err = K_DNS_SERVICE_ERR_NO_ERROR;

        for attempt in 1..=MAX_NAME_ATTEMPTS {
            let candidate_c = if attempt == 1 {
                name_c.clone()
            } else {
                let candidate = format!("{} ({})", name, attempt);
                // A renamed instance is still a single DNS label
                if candidate.len() > crate::MAX_LABEL_BYTES {
                    break;
                }
                match CString::new(candidate) {
                    Ok(c) => c,
                    Err(_) => break,
                }
            };

            sd_ref = ptr::null_mut();
            err = unsafe {
                (lib.register)(
                    &mut sd_ref,
                    0,
                    0,
                    candidate_c.as_ptr(),
                    reg_type.as_ptr(),
                    domain_ptr,
                    host_ptr,
                    port.to_be(),
                    txt_len,
                    txt_ptr,
                    Some(register_callback),
                    ctx_ptr as *mut c_void,
                )
            };

            if err != K_DNS_SERVICE_ERR_NAME_CONFLICT {
                break;
            }

            // dns_sd.h leaves *sdRef untouched on failure, but Avahi's compat
            // layer is a separate implementation - release anything it did hand
            // back before trying the next name.
            if !sd_ref.is_null() {
                unsafe { (lib.ref_deallocate)(sd_ref) };
                sd_ref = ptr::null_mut();
            }
        }

        if txt.is_some() {
            unsafe {
                (lib.txt_record_deallocate)(&mut txt_ref);
            }
        }

        if let Err(e) = check_error(err) {
            unsafe { drop(Box::from_raw(ctx_ptr)) };
            return Err(e);
        }

        if sd_ref.is_null() {
            unsafe { drop(Box::from_raw(ctx_ptr)) };
            return Err("DNSServiceRegister returned null".into());
        }

        // Start event loop thread
        let sd_ref_copy = sd_ref as usize;
        let stop_flag_clone = stop_flag.clone();
        // SAFETY: ctx_ptr stays alive until stop() reclaims it, and stop() joins
        // this thread first.
        let thread_callback = unsafe { (*ctx_ptr).callback.clone() };
        let dead_clone = dead.clone();

        let thread = thread::spawn(move || {
            let sd_ref = sd_ref_copy as DNSServiceRef;
            let lib = match DnsSdLibrary::get() {
                Ok(lib) => lib,
                Err(_) => return,
            };

            loop {
                if *stop_flag_clone.lock().unwrap() || dead_clone.load(Ordering::SeqCst) {
                    break;
                }

                unsafe {
                    let fd = (lib.ref_sock_fd)(sd_ref);
                    if fd < 0 {
                        // The daemon went away, so the service is no longer
                        // published even though this handle still looks alive.
                        thread_callback(
                            "error",
                            "advertisement lost its connection to the DNS-SD daemon",
                        );
                        break;
                    }

                    let mut pfd = sys::pollfd {
                        fd: fd as _,
                        events: sys::POLLIN,
                        revents: 0,
                    };

                    let ready = sys::poll(&mut pfd, 1, 100);

                    if ready > 0 {
                        let err = (lib.process_result)(sd_ref);
                        if err != K_DNS_SERVICE_ERR_NO_ERROR {
                            thread_callback(
                                "error",
                                &format!("advertisement stopped: {}", error_message(err)),
                            );
                            break;
                        }
                    }
                }
            }
        });

        Ok(NativeAdvertisement {
            sd_ref,
            stop_flag,
            thread: Some(thread),
            _context: ctx_ptr,
            stopped: false,
        })
    }

    /// Stop advertising
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        
        *self.stop_flag.lock().unwrap() = true;
        
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }

        if !self.sd_ref.is_null() {
            if let Ok(lib) = DnsSdLibrary::get() {
                unsafe {
                    (lib.ref_deallocate)(self.sd_ref);
                }
            }
            self.sd_ref = ptr::null_mut();
        }

        if !self._context.is_null() {
            unsafe {
                let _ = Box::from_raw(self._context);
            }
            self._context = ptr::null_mut();
        }
    }
}

impl Drop for NativeAdvertisement {
    fn drop(&mut self) {
        self.stop();
    }
}
