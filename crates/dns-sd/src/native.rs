//! Native DNS-SD backend using libloading to dynamically load dns_sd library

use crate::ffi::*;
use libloading::Library;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Global library instance
static LIBRARY: OnceCell<Result<DnsSdLibrary, String>> = OnceCell::new();

/// Loaded DNS-SD library with function pointers
pub struct DnsSdLibrary {
    _lib: Library,
    pub browse: FnDNSServiceBrowse,
    pub resolve: FnDNSServiceResolve,
    pub register: FnDNSServiceRegister,
    pub get_addr_info: Option<FnDNSServiceGetAddrInfo>, // Optional: missing on Linux Avahi
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
pub fn is_available() -> bool {
    DnsSdLibrary::get().is_ok()
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

/// Shared callback type for thread-safe access
type SharedCallback = Arc<dyn Fn(&str, ServiceInfo) + Send + Sync + 'static>;

/// Context passed to browse callback
struct BrowseContext {
    callback: SharedCallback,
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
        if error_code != K_DNS_SERVICE_ERR_NO_ERROR {
            return;
        }

        let ctx = &*(context as *const BrowseContext);
        
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
    poll_service_loop(lib, resolve_ref, 3000, || {
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

                if sa_family == libc::AF_INET as u16 {
                    let addr4 = address as *const libc::sockaddr_in;
                    let ip_bytes = (*addr4).sin_addr.s_addr.to_ne_bytes();
                    let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                    ip_str = IpAddr::V4(ip).to_string();
                } else if sa_family == libc::AF_INET6 as u16 {
                    let addr6 = address as *const libc::sockaddr_in6;
                    let ip_bytes = (*addr6).sin6_addr.s6_addr;
                    let ip = Ipv6Addr::from(ip_bytes);
                    ip_str = IpAddr::V6(ip).to_string();
                }

                if !ip_str.is_empty() && !state.info.addresses.contains(&ip_str) {
                    state.info.addresses.push(ip_str);
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
            let timeout = 2000;
            // Simply poll for a while to collect addresses
            poll_service_loop(lib, addr_ref, timeout, || false);

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
             
            let timeout = 2000;
            let start = std::time::Instant::now();
            
            // Poll both refs
            while start.elapsed().as_millis() < timeout {
                 if !query_ref.is_null() {
                      unsafe { (lib.process_result)(query_ref); }
                 }
                 if !query_ref6.is_null() {
                      unsafe { (lib.process_result)(query_ref6); }
                 }
                 // Small sleep to prevent busy loop
                 thread::sleep(Duration::from_millis(50));
            }

            unsafe {
                if !query_ref.is_null() { (lib.ref_deallocate)(query_ref); }
                if !query_ref6.is_null() { (lib.ref_deallocate)(query_ref6); }
            }
        }
    }
}

/// Helper to poll service ref with timeout and early exit predicate
fn poll_service_loop<F>(lib: &DnsSdLibrary, sd_ref: DNSServiceRef, timeout_ms: u128, mut should_exit: F) 
where F: FnMut() -> bool {
    let start = std::time::Instant::now();
    
    while start.elapsed().as_millis() < timeout_ms {
        if should_exit() {
            break;
        }

        unsafe {
            let fd = (lib.ref_sock_fd)(sd_ref);
            if fd < 0 { break; }

            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let remaining = timeout_ms.saturating_sub(start.elapsed().as_millis()).max(1) as i32;
            let poll_timeout = remaining.min(100); // Poll in 100ms chunks to check predicate

            let ready = libc::poll(&mut pfd, 1, poll_timeout);

            if ready > 0 {
                (lib.process_result)(sd_ref);
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
    pub fn new<F>(service_type: &str, callback: F) -> Result<Self, String>
    where
        F: Fn(&str, ServiceInfo) + Send + Sync + 'static,
    {
        let lib = DnsSdLibrary::get()?;
        
        let stop_flag = Arc::new(Mutex::new(false));
        
        let ctx = Box::new(BrowseContext {
            callback: Arc::new(callback),
        });
        let ctx_ptr = Box::into_raw(ctx);

        let reg_type = CString::new(service_type).map_err(|e| e.to_string())?;
        
        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        
        let err = unsafe {
            (lib.browse)(
                &mut sd_ref,
                0,
                0,
                reg_type.as_ptr(),
                ptr::null(),
                Some(browse_callback),
                ctx_ptr as *mut c_void,
            )
        };

        check_error(err)?;

        if sd_ref.is_null() {
            return Err("DNSServiceBrowse returned null".into());
        }

        // Start event loop thread
        let sd_ref_copy = sd_ref as usize;
        let stop_flag_clone = stop_flag.clone();
        
        let thread = thread::spawn(move || {
            let sd_ref = sd_ref_copy as DNSServiceRef;
            let lib = match DnsSdLibrary::get() {
                Ok(lib) => lib,
                Err(_) => return,
            };

            loop {
                if *stop_flag_clone.lock().unwrap() {
                    break;
                }

                unsafe {
                    let fd = (lib.ref_sock_fd)(sd_ref);
                    if fd < 0 {
                        break;
                    }

                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };

                    let ready = libc::poll(&mut pfd, 1, 100);

                    if ready > 0 {
                        let err = (lib.process_result)(sd_ref);
                        if err != K_DNS_SERVICE_ERR_NO_ERROR {
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
    callback: Box<dyn Fn(&str, &str) + Send + 'static>,
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
            (ctx.callback)("error", &format!("DNS-SD error: {}", error_code));
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
        port: u16,
        txt: Option<&HashMap<String, String>>,
        callback: F,
    ) -> Result<Self, String>
    where
        F: Fn(&str, &str) + Send + 'static,
    {
        let lib = DnsSdLibrary::get()?;
        
        let stop_flag = Arc::new(Mutex::new(false));
        
        let ctx = Box::new(RegisterContext {
            callback: Box::new(callback),
        });
        let ctx_ptr = Box::into_raw(ctx);

        let name_c = CString::new(name).map_err(|e| e.to_string())?;
        let reg_type = CString::new(service_type).map_err(|e| e.to_string())?;
        
        // Build TXT record
        let mut txt_ref: TXTRecordRef = [0u8; 16];
        let (txt_len, txt_ptr) = if let Some(txt_map) = txt {
            unsafe {
                (lib.txt_record_create)(&mut txt_ref, 0, ptr::null_mut());
                
                for (k, v) in txt_map {
                    let key_c = CString::new(k.as_str()).unwrap();
                    let _ = (lib.txt_record_set_value)(
                        &mut txt_ref,
                        key_c.as_ptr(),
                        v.len() as u8,
                        v.as_ptr() as *const c_void,
                    );
                }
                
                let len = (lib.txt_record_get_length)(&txt_ref);
                let ptr = (lib.txt_record_get_bytes_ptr)(&txt_ref);
                (len, ptr)
            }
        } else {
            (0, ptr::null())
        };

        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        
        let err = unsafe {
            (lib.register)(
                &mut sd_ref,
                0,
                0,
                name_c.as_ptr(),
                reg_type.as_ptr(),
                ptr::null(),
                ptr::null(),
                port.to_be(),
                txt_len,
                txt_ptr,
                Some(register_callback),
                ctx_ptr as *mut c_void,
            )
        };

        if txt.is_some() {
            unsafe {
                (lib.txt_record_deallocate)(&mut txt_ref);
            }
        }

        check_error(err)?;

        if sd_ref.is_null() {
            return Err("DNSServiceRegister returned null".into());
        }

        // Start event loop thread
        let sd_ref_copy = sd_ref as usize;
        let stop_flag_clone = stop_flag.clone();
        
        let thread = thread::spawn(move || {
            let sd_ref = sd_ref_copy as DNSServiceRef;
            let lib = match DnsSdLibrary::get() {
                Ok(lib) => lib,
                Err(_) => return,
            };

            loop {
                if *stop_flag_clone.lock().unwrap() {
                    break;
                }

                unsafe {
                    let fd = (lib.ref_sock_fd)(sd_ref);
                    if fd < 0 {
                        break;
                    }

                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };

                    let ready = libc::poll(&mut pfd, 1, 100);

                    if ready > 0 {
                        let err = (lib.process_result)(sd_ref);
                        if err != K_DNS_SERVICE_ERR_NO_ERROR {
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
