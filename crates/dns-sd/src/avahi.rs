//! Native DNS-SD backend using libavahi-client (dlopen), Linux only.
//! macOS/Windows use the dns_sd.h backend in bonjour.rs instead.

use libloading::Library;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ----------------------------------------------------------------
// FFI layer - opaque types, enums and function signatures taken from
// /usr/include/avahi-{client,common}/*.h
// ----------------------------------------------------------------

type AvahiClient = c_void;
type AvahiSimplePoll = c_void;
type AvahiPoll = c_void;
type AvahiEntryGroup = c_void;
type AvahiServiceBrowser = c_void;
type AvahiServiceResolver = c_void;
type AvahiStringList = c_void;

type AvahiIfIndex = i32;
type AvahiProtocol = i32;
type AvahiClientState = c_int;
type AvahiClientFlags = c_int;
type AvahiEntryGroupState = c_int;
type AvahiPublishFlags = c_int;
type AvahiLookupFlags = c_int;
type AvahiLookupResultFlags = c_int;
type AvahiBrowserEvent = c_int;
type AvahiResolverEvent = c_int;

const AVAHI_IF_UNSPEC: AvahiIfIndex = -1;
const AVAHI_PROTO_UNSPEC: AvahiProtocol = -1;
const AVAHI_PROTO_INET: AvahiProtocol = 0;
const AVAHI_PROTO_INET6: AvahiProtocol = 1;

// AvahiClientState: a superset of AvahiServerState (AVAHI_SERVER_INVALID=0,
// REGISTERING=1, RUNNING=2, COLLISION=3, FAILURE=4), plus two client-only
// values. Without AVAHI_CLIENT_NO_FAIL (never passed here), avahi_client_new()
// only ever returns non-null once already past REGISTERING, so RUNNING itself
// is never checked for explicitly - only FAILURE, reported asynchronously.
const AVAHI_CLIENT_FAILURE: AvahiClientState = 100;

const AVAHI_ENTRY_GROUP_ESTABLISHED: AvahiEntryGroupState = 2;
const AVAHI_ENTRY_GROUP_COLLISION: AvahiEntryGroupState = 3;
const AVAHI_ENTRY_GROUP_FAILURE: AvahiEntryGroupState = 4;

const AVAHI_BROWSER_NEW: AvahiBrowserEvent = 0;
const AVAHI_BROWSER_REMOVE: AvahiBrowserEvent = 1;
const AVAHI_BROWSER_FAILURE: AvahiBrowserEvent = 4;

const AVAHI_RESOLVER_FOUND: AvahiResolverEvent = 0;

const AVAHI_OK: c_int = 0;
const AVAHI_ERR_COLLISION: c_int = -8;

/// Protocol-independent address. Layout matches AvahiAddress from address.h:
/// `{ AvahiProtocol proto; union { AvahiIPv6Address ipv6; AvahiIPv4Address ipv4; uint8_t data[1]; } data; }`.
/// The union's largest member is the 16-byte IPv6 form, and IPv4's 4-byte
/// network-order `address` occupies the same leading bytes, so reading the
/// first N bytes for the active protocol is correct either way.
#[repr(C)]
struct AvahiAddress {
    proto: AvahiProtocol,
    data: [u8; 16],
}

fn read_avahi_address(addr: *const AvahiAddress) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    unsafe {
        match (*addr).proto {
            AVAHI_PROTO_INET => {
                let b = &(*addr).data;
                Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            }
            AVAHI_PROTO_INET6 => Some(IpAddr::V6(Ipv6Addr::from((*addr).data))),
            _ => None,
        }
    }
}

type AvahiClientCallback =
    unsafe extern "C" fn(*mut AvahiClient, AvahiClientState, *mut c_void);
type AvahiEntryGroupCallback =
    unsafe extern "C" fn(*mut AvahiEntryGroup, AvahiEntryGroupState, *mut c_void);
type AvahiServiceBrowserCallback = unsafe extern "C" fn(
    *mut AvahiServiceBrowser,
    AvahiIfIndex,
    AvahiProtocol,
    AvahiBrowserEvent,
    *const c_char,
    *const c_char,
    *const c_char,
    AvahiLookupResultFlags,
    *mut c_void,
);
type AvahiServiceResolverCallback = unsafe extern "C" fn(
    *mut AvahiServiceResolver,
    AvahiIfIndex,
    AvahiProtocol,
    AvahiResolverEvent,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const AvahiAddress,
    u16,
    *mut AvahiStringList,
    AvahiLookupResultFlags,
    *mut c_void,
);

type FnSimplePollNew = unsafe extern "C" fn() -> *mut AvahiSimplePoll;
type FnSimplePollFree = unsafe extern "C" fn(*mut AvahiSimplePoll);
type FnSimplePollGet = unsafe extern "C" fn(*mut AvahiSimplePoll) -> *const AvahiPoll;
type FnSimplePollIterate = unsafe extern "C" fn(*mut AvahiSimplePoll, c_int) -> c_int;

type FnStringListAddPair =
    unsafe extern "C" fn(*mut AvahiStringList, *const c_char, *const c_char) -> *mut AvahiStringList;
type FnStringListFree = unsafe extern "C" fn(*mut AvahiStringList);
type FnStringListGetNext = unsafe extern "C" fn(*mut AvahiStringList) -> *mut AvahiStringList;
type FnStringListGetPair = unsafe extern "C" fn(
    *mut AvahiStringList,
    *mut *mut c_char,
    *mut *mut c_char,
    *mut usize,
) -> c_int;

type FnFree = unsafe extern "C" fn(*mut c_void);
type FnStrError = unsafe extern "C" fn(c_int) -> *const c_char;

type FnClientNew = unsafe extern "C" fn(
    *const AvahiPoll,
    AvahiClientFlags,
    AvahiClientCallback,
    *mut c_void,
    *mut c_int,
) -> *mut AvahiClient;
type FnClientFree = unsafe extern "C" fn(*mut AvahiClient);
type FnClientErrno = unsafe extern "C" fn(*mut AvahiClient) -> c_int;

type FnEntryGroupNew =
    unsafe extern "C" fn(*mut AvahiClient, AvahiEntryGroupCallback, *mut c_void) -> *mut AvahiEntryGroup;
type FnEntryGroupCommit = unsafe extern "C" fn(*mut AvahiEntryGroup) -> c_int;
type FnEntryGroupReset = unsafe extern "C" fn(*mut AvahiEntryGroup) -> c_int;
#[allow(clippy::too_many_arguments)]
type FnEntryGroupAddServiceStrLst = unsafe extern "C" fn(
    *mut AvahiEntryGroup,
    AvahiIfIndex,
    AvahiProtocol,
    AvahiPublishFlags,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    u16,
    *mut AvahiStringList,
) -> c_int;
type FnEntryGroupAddServiceSubtype = unsafe extern "C" fn(
    *mut AvahiEntryGroup,
    AvahiIfIndex,
    AvahiProtocol,
    AvahiPublishFlags,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
) -> c_int;

type FnServiceBrowserNew = unsafe extern "C" fn(
    *mut AvahiClient,
    AvahiIfIndex,
    AvahiProtocol,
    *const c_char,
    *const c_char,
    AvahiLookupFlags,
    AvahiServiceBrowserCallback,
    *mut c_void,
) -> *mut AvahiServiceBrowser;

#[allow(clippy::too_many_arguments)]
type FnServiceResolverNew = unsafe extern "C" fn(
    *mut AvahiClient,
    AvahiIfIndex,
    AvahiProtocol,
    *const c_char,
    *const c_char,
    *const c_char,
    AvahiProtocol,
    AvahiLookupFlags,
    AvahiServiceResolverCallback,
    *mut c_void,
) -> *mut AvahiServiceResolver;

type FnServiceResolverFree = unsafe extern "C" fn(*mut AvahiServiceResolver) -> c_int;

/// Loaded libavahi-client/libavahi-common function pointers.
struct AvahiLibrary {
    _lib_common: Library,
    _lib_client: Library,
    simple_poll_new: FnSimplePollNew,
    simple_poll_free: FnSimplePollFree,
    simple_poll_get: FnSimplePollGet,
    simple_poll_iterate: FnSimplePollIterate,
    string_list_add_pair: FnStringListAddPair,
    string_list_free: FnStringListFree,
    string_list_get_next: FnStringListGetNext,
    string_list_get_pair: FnStringListGetPair,
    free: FnFree,
    strerror: FnStrError,
    client_new: FnClientNew,
    client_free: FnClientFree,
    client_errno: FnClientErrno,
    entry_group_new: FnEntryGroupNew,
    entry_group_commit: FnEntryGroupCommit,
    entry_group_reset: FnEntryGroupReset,
    entry_group_add_service_strlst: FnEntryGroupAddServiceStrLst,
    entry_group_add_service_subtype: FnEntryGroupAddServiceSubtype,
    service_browser_new: FnServiceBrowserNew,
    service_resolver_new: FnServiceResolverNew,
    service_resolver_free: FnServiceResolverFree,
}

// SAFETY: avahi-client's functions are safe to call from any thread as long as
// calls touching a given AvahiClient/AvahiSimplePoll are externally
// synchronized, which every caller in this file does (single poll thread per
// handle, constructor runs before that thread starts).
unsafe impl Send for AvahiLibrary {}
unsafe impl Sync for AvahiLibrary {}

static LIBRARY: OnceCell<Result<AvahiLibrary, String>> = OnceCell::new();

impl AvahiLibrary {
    fn load() -> Result<Self, String> {
        // SAFETY: loading external libraries by their runtime SONAME, same
        // convention as the compat shim's own "libdns_sd.so.1" lookup.
        let lib_common = unsafe { Library::new("libavahi-common.so.3") }
            .map_err(|e| format!("Failed to load libavahi-common.so.3: {}", e))?;
        let lib_client = unsafe { Library::new("libavahi-client.so.3") }
            .map_err(|e| format!("Failed to load libavahi-client.so.3: {}", e))?;

        macro_rules! sym {
            ($lib:expr, $name:literal, $ty:ty) => {
                unsafe {
                    *$lib
                        .get::<$ty>(concat!($name, "\0").as_bytes())
                        .map_err(|e| format!(concat!($name, ": {}"), e))?
                }
            };
        }

        Ok(AvahiLibrary {
            simple_poll_new: sym!(lib_common, "avahi_simple_poll_new", FnSimplePollNew),
            simple_poll_free: sym!(lib_common, "avahi_simple_poll_free", FnSimplePollFree),
            simple_poll_get: sym!(lib_common, "avahi_simple_poll_get", FnSimplePollGet),
            simple_poll_iterate: sym!(lib_common, "avahi_simple_poll_iterate", FnSimplePollIterate),
            string_list_add_pair: sym!(lib_common, "avahi_string_list_add_pair", FnStringListAddPair),
            string_list_free: sym!(lib_common, "avahi_string_list_free", FnStringListFree),
            string_list_get_next: sym!(lib_common, "avahi_string_list_get_next", FnStringListGetNext),
            string_list_get_pair: sym!(lib_common, "avahi_string_list_get_pair", FnStringListGetPair),
            free: sym!(lib_common, "avahi_free", FnFree),
            strerror: sym!(lib_common, "avahi_strerror", FnStrError),
            client_new: sym!(lib_client, "avahi_client_new", FnClientNew),
            client_free: sym!(lib_client, "avahi_client_free", FnClientFree),
            client_errno: sym!(lib_client, "avahi_client_errno", FnClientErrno),
            entry_group_new: sym!(lib_client, "avahi_entry_group_new", FnEntryGroupNew),
            entry_group_commit: sym!(lib_client, "avahi_entry_group_commit", FnEntryGroupCommit),
            entry_group_reset: sym!(lib_client, "avahi_entry_group_reset", FnEntryGroupReset),
            entry_group_add_service_strlst: sym!(
                lib_client,
                "avahi_entry_group_add_service_strlst",
                FnEntryGroupAddServiceStrLst
            ),
            entry_group_add_service_subtype: sym!(
                lib_client,
                "avahi_entry_group_add_service_subtype",
                FnEntryGroupAddServiceSubtype
            ),
            service_browser_new: sym!(lib_client, "avahi_service_browser_new", FnServiceBrowserNew),
            service_resolver_new: sym!(lib_client, "avahi_service_resolver_new", FnServiceResolverNew),
            service_resolver_free: sym!(lib_client, "avahi_service_resolver_free", FnServiceResolverFree),
            _lib_common: lib_common,
            _lib_client: lib_client,
        })
    }

    fn get() -> Result<&'static AvahiLibrary, String> {
        LIBRARY.get_or_init(Self::load).as_ref().map_err(|e| e.clone())
    }

    fn error_message(&self, err: c_int) -> String {
        let msg = unsafe {
            let ptr = (self.strerror)(err);
            if ptr.is_null() {
                "unknown avahi error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        format!("{} ({})", msg, err)
    }
}

/// How many names to try when resolving a conflict, per RFC 6762 section 9.
/// Matches the Bonjour-path constant in native.rs for cross-backend parity.
const MAX_NAME_ATTEMPTS: u32 = 10;

/// How long to wait for avahi to establish (or reject) a registration before
/// giving up on a single attempt.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(5);

// ----------------------------------------------------------------
// Daemon availability
// ----------------------------------------------------------------

static AVAILABILITY_CACHE: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

pub fn invalidate_availability() {
    *AVAILABILITY_CACHE.lock().unwrap() = None;
}

/// Why publishing via the fallback would be harmful right now; `None` if safe.
///
/// Being unable to reach avahi-daemon is not the same as it not running (it is
/// up, libavahi-client3 just is not installed). Publishing anyway makes this a
/// second responder: our own name probe gets answered via the other one, the
/// fallback renames itself, and the service lands on the wire twice. Browsing
/// is benign and deliberately not guarded.
///
/// Probes the pidfile rather than /run/avahi-daemon/socket, since that socket
/// is usually systemd socket-activated and connecting would start the daemon
/// being probed for. Fails open; misses a non-Avahi responder, and a container
/// sharing the host netns but not /run.
pub fn fallback_publish_conflict() -> Option<String> {
    if std::env::var_os("DNS_SD_FORCE_FALLBACK_ADVERTISE").is_some() {
        return None;
    }

    let pid = std::fs::read_to_string("/run/avahi-daemon/pid").ok()?;
    let pid = pid.trim();
    if pid.is_empty() {
        return None;
    }
    // Confirm the pid is actually avahi-daemon; a stale pidfile pointing at a
    // recycled pid would otherwise block publishing for no reason.
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    if comm.trim() != "avahi-daemon" {
        return None;
    }

    Some(
        "avahi-daemon is running but could not be reached through libavahi-client, so \
         advertising would publish this service twice on the network (once via the \
         pure-Rust fallback, once renamed by the conflict that causes) and degrade mDNS \
         for every DNS-SD client on this network. Fix this by installing libavahi-client3 \
         so the native backend can be used, or by disabling avahi-daemon so the fallback \
         is the only responder. Browsing is unaffected. To publish anyway, set \
         DNS_SD_FORCE_FALLBACK_ADVERTISE=1."
            .to_string(),
    )
}

pub fn is_available() -> bool {
    const CACHE_TTL: Duration = Duration::from_secs(5);

    let mut cache = AVAILABILITY_CACHE.lock().unwrap();
    if let Some((checked_at, available)) = *cache {
        if checked_at.elapsed() < CACHE_TTL {
            return available;
        }
    }

    let available = probe_daemon();
    *cache = Some((Instant::now(), available));
    available
}

/// Connect to avahi-daemon and immediately disconnect. Without
/// AVAHI_CLIENT_NO_FAIL, avahi_client_new() itself fails synchronously
/// (returns NULL) if the daemon isn't reachable, so this is a direct
/// connectivity check rather than a heuristic - unlike the old compat-shim
/// probe, nothing here is ever guaranteed-unsupported.
fn probe_daemon() -> bool {
    let lib = match AvahiLibrary::get() {
        Ok(lib) => lib,
        Err(_) => return false,
    };

    let simple_poll = unsafe { (lib.simple_poll_new)() };
    if simple_poll.is_null() {
        return false;
    }

    unsafe extern "C" fn noop_client_callback(
        _client: *mut AvahiClient,
        _state: AvahiClientState,
        _userdata: *mut c_void,
    ) {
    }

    let mut error: c_int = 0;
    let client = unsafe {
        (lib.client_new)(
            (lib.simple_poll_get)(simple_poll),
            0,
            noop_client_callback,
            ptr::null_mut(),
            &mut error,
        )
    };

    let available = !client.is_null();
    if !client.is_null() {
        unsafe { (lib.client_free)(client) };
    }
    unsafe { (lib.simple_poll_free)(simple_poll) };
    available
}

// ----------------------------------------------------------------
// Shared service info type (mirrors the Bonjour-path shape exactly, since
// lib.rs consumes this struct directly regardless of platform)
// ----------------------------------------------------------------

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

type SharedBrowseCallback = Arc<dyn Fn(&str, ServiceInfo) + Send + Sync + 'static>;
type SharedRegisterCallback = Arc<dyn Fn(&str, &str) + Send + Sync + 'static>;

/// avahi-client hands back unqualified strings ("local"), while the rest of
/// the crate uses the fully-qualified form. The JS layer keys services on
/// name + type + domain, so a mismatch silently breaks events across a
/// backend switch.
fn qualify(s: &str) -> String {
    if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{}.", s)
    }
}

fn split_service_type(service_type: &str) -> (&str, Vec<&str>) {
    let mut parts = service_type.split(',');
    let base = parts.next().unwrap_or(service_type);
    (base, parts.collect())
}

fn txt_to_string_list(lib: &AvahiLibrary, txt: &HashMap<String, String>) -> Result<*mut AvahiStringList, String> {
    let mut list: *mut AvahiStringList = ptr::null_mut();
    for (k, v) in txt {
        if k.len() + 1 + v.len() > 255 {
            return Err(format!(
                "TXT record entry '{}' is {} bytes, over the 255 byte DNS-SD limit",
                k,
                k.len() + 1 + v.len()
            ));
        }
        let key_c = CString::new(k.as_str())
            .map_err(|_| format!("TXT record key '{}' contains a NUL byte", k.escape_debug()))?;
        let val_c = CString::new(v.as_str())
            .map_err(|_| format!("TXT record value for '{}' contains a NUL byte", k))?;
        list = unsafe { (lib.string_list_add_pair)(list, key_c.as_ptr(), val_c.as_ptr()) };
    }
    Ok(list)
}

fn parse_avahi_txt(lib: &AvahiLibrary, mut node: *mut AvahiStringList) -> HashMap<String, String> {
    let mut map = HashMap::new();
    while !node.is_null() {
        let mut key: *mut c_char = ptr::null_mut();
        let mut value: *mut c_char = ptr::null_mut();
        let mut size: usize = 0;
        let ok = unsafe { (lib.string_list_get_pair)(node, &mut key, &mut value, &mut size) };
        if ok == 0 && !key.is_null() {
            let key_str = unsafe { CStr::from_ptr(key).to_string_lossy().into_owned() };
            let value_str = if value.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(value).to_string_lossy().into_owned() }
            };
            map.insert(key_str, value_str);
            unsafe {
                (lib.free)(key as *mut c_void);
                if !value.is_null() {
                    (lib.free)(value as *mut c_void);
                }
            }
        }
        node = unsafe { (lib.string_list_get_next)(node) };
    }
    map
}

// ----------------------------------------------------------------
// Browse
// ----------------------------------------------------------------

type ServiceKey = (String, String, String);
/// A ServiceKey plus the (interface, protocol) leg it was seen on.
type ResolverKey = (ServiceKey, AvahiIfIndex, AvahiProtocol);

struct ResolveState {
    info: ServiceInfo,
    last_update: Instant,
}

struct BrowseShared {
    callback: SharedBrowseCallback,
    dead: Arc<AtomicBool>,
    client: AtomicUsize,
    services: Mutex<HashMap<ServiceKey, Arc<Mutex<ResolveState>>>>,
    /// Live resolvers -> (resolver, boxed ctx). The interface/protocol MUST
    /// stay in the key: Avahi reports a multi-homed instance once per leg and
    /// each resolver returns only its own leg's address, so a coarser key
    /// silently collapses the host to one address. Keyed rather than appended
    /// so a flapping service reuses its entry instead of stacking a resolver
    /// per BROWSER_NEW; freed on BROWSER_REMOVE, survivors at stop().
    resolvers: Mutex<HashMap<ResolverKey, (usize, usize)>>,
}

pub struct NativeBrowser {
    client: usize,
    simple_poll: usize,
    client_ctx: usize,
    browser_ctx: usize,
    stop_flag: Arc<Mutex<bool>>,
    thread: Option<thread::JoinHandle<()>>,
    shared: Arc<BrowseShared>,
    stopped: bool,
}

unsafe impl Send for NativeBrowser {}

unsafe extern "C" fn browse_client_callback(
    _client: *mut AvahiClient,
    state: AvahiClientState,
    userdata: *mut c_void,
) {
    let shared = unsafe { &*(userdata as *const Arc<BrowseShared>) };
    if state == AVAHI_CLIENT_FAILURE {
        if !shared.dead.swap(true, Ordering::SeqCst) {
            invalidate_availability();
            (shared.callback)(
                "error",
                ServiceInfo::error("browse connection to the DNS-SD daemon was lost".to_string()),
            );
        }
    }
}

unsafe extern "C" fn browser_callback(
    _b: *mut AvahiServiceBrowser,
    interface: AvahiIfIndex,
    protocol: AvahiProtocol,
    event: AvahiBrowserEvent,
    name: *const c_char,
    service_type: *const c_char,
    domain: *const c_char,
    _flags: AvahiLookupResultFlags,
    userdata: *mut c_void,
) {
    let shared = unsafe { &*(userdata as *const Arc<BrowseShared>) };

    if event == AVAHI_BROWSER_FAILURE {
        let lib = match AvahiLibrary::get() {
            Ok(lib) => lib,
            Err(_) => return,
        };
        let client = shared.client.load(Ordering::SeqCst) as *mut AvahiClient;
        let err = if client.is_null() {
            0
        } else {
            unsafe { (lib.client_errno)(client) }
        };
        if !shared.dead.swap(true, Ordering::SeqCst) {
            invalidate_availability();
            (shared.callback)(
                "error",
                ServiceInfo::error(format!("browse stopped: {}", lib.error_message(err))),
            );
        }
        return;
    }

    if event != AVAHI_BROWSER_NEW && event != AVAHI_BROWSER_REMOVE {
        // AVAHI_BROWSER_CACHE_EXHAUSTED / AVAHI_BROWSER_ALL_FOR_NOW: no-ops.
        return;
    }

    let name = unsafe { CStr::from_ptr(name).to_string_lossy().into_owned() };
    let service_type_s = qualify(&unsafe { CStr::from_ptr(service_type).to_string_lossy().into_owned() });
    let domain_s = qualify(&unsafe { CStr::from_ptr(domain).to_string_lossy().into_owned() });
    let key: ServiceKey = (name.clone(), service_type_s.clone(), domain_s.clone());

    if event == AVAHI_BROWSER_REMOVE {
        shared.services.lock().unwrap().remove(&key);
        // Safe from inside the browser callback: both run on this browse's
        // poll thread, and freeing the resolver first guarantees no callback
        // can fire against the Box dropped after it.
        let rkey: ResolverKey = (key.clone(), interface, protocol);
        if let Some((resolver, ctx)) = shared.resolvers.lock().unwrap().remove(&rkey) {
            if let Ok(lib) = AvahiLibrary::get() {
                unsafe { (lib.service_resolver_free)(resolver as *mut AvahiServiceResolver) };
            }
            unsafe { drop(Box::from_raw(ctx as *mut (Arc<BrowseShared>, ServiceKey))) };
        }
        (shared.callback)(
            "serviceLost",
            ServiceInfo {
                name,
                service_type: service_type_s,
                domain: domain_s,
                host_name: String::new(),
                addresses: vec![],
                port: 0,
                txt: HashMap::new(),
                ttl: 0,
            },
        );
        return;
    }

    // AVAHI_BROWSER_NEW: resolve this instance. A resolver stays open for the
    // life of the browse (freed at stop()) so it can report address changes,
    // mirroring the "keep it open" guidance in avahi-common/lookup.h.
    let lib = match AvahiLibrary::get() {
        Ok(lib) => lib,
        Err(_) => return,
    };
    let client = shared.client.load(Ordering::SeqCst) as *mut AvahiClient;
    if client.is_null() {
        return;
    }

    // NEW can repeat for a leg we already track (flap, or cache refresh); the
    // live resolver keeps reporting that leg's updates.
    let rkey: ResolverKey = (key.clone(), interface, protocol);
    if shared.resolvers.lock().unwrap().contains_key(&rkey) {
        return;
    }

    let name_c = match CString::new(name.as_str()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let type_c = match CString::new(service_type_s.as_str()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let domain_c = match CString::new(domain_s.as_str()) {
        Ok(c) => c,
        Err(_) => return,
    };

    shared.services.lock().unwrap().entry(key.clone()).or_insert_with(|| {
        Arc::new(Mutex::new(ResolveState {
            info: ServiceInfo {
                name: name.clone(),
                service_type: service_type_s.clone(),
                domain: domain_s.clone(),
                host_name: String::new(),
                addresses: vec![],
                port: 0,
                txt: HashMap::new(),
                ttl: 0,
            },
            last_update: Instant::now(),
        }))
    });

    let resolver_ctx = Box::into_raw(Box::new((shared.clone() as Arc<BrowseShared>, key.clone())));
    let resolver = unsafe {
        (lib.service_resolver_new)(
            client,
            interface,
            protocol,
            name_c.as_ptr(),
            type_c.as_ptr(),
            domain_c.as_ptr(),
            AVAHI_PROTO_UNSPEC,
            0,
            resolver_callback,
            resolver_ctx as *mut c_void,
        )
    };

    if resolver.is_null() {
        unsafe { drop(Box::from_raw(resolver_ctx)) };
        return;
    }

    shared
        .resolvers
        .lock()
        .unwrap()
        .insert(rkey, (resolver as usize, resolver_ctx as usize));
}

unsafe extern "C" fn resolver_callback(
    _r: *mut AvahiServiceResolver,
    _interface: AvahiIfIndex,
    _protocol: AvahiProtocol,
    event: AvahiResolverEvent,
    _name: *const c_char,
    _service_type: *const c_char,
    _domain: *const c_char,
    host_name: *const c_char,
    addr: *const AvahiAddress,
    port: u16,
    txt: *mut AvahiStringList,
    _flags: AvahiLookupResultFlags,
    userdata: *mut c_void,
) {
    if event != AVAHI_RESOLVER_FOUND {
        // AVAHI_RESOLVER_FAILURE: transient (e.g. the instance just vanished
        // mid-resolve). Leave the resolver open; a future FOUND or the
        // browser's REMOVE event will settle it.
        return;
    }

    let (shared, key) = unsafe { &*(userdata as *const (Arc<BrowseShared>, ServiceKey)) };
    let lib = match AvahiLibrary::get() {
        Ok(lib) => lib,
        Err(_) => return,
    };

    let state = match shared.services.lock().unwrap().get(key) {
        Some(s) => s.clone(),
        None => return,
    };

    let ip = read_avahi_address(addr);
    let host = if host_name.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(host_name).to_string_lossy().into_owned() }
    };
    let txt_map = parse_avahi_txt(lib, txt);

    let mut s = state.lock().unwrap();
    s.info.host_name = host;
    s.info.port = port;
    s.info.txt = txt_map;
    let mut changed = true;
    if let Some(ip) = ip {
        let ip_str = ip.to_string();
        if !s.info.addresses.contains(&ip_str) {
            s.info.addresses.push(ip_str);
        } else {
            changed = false;
        }
    }
    s.last_update = Instant::now();
    let info = s.info.clone();
    drop(s);

    if changed {
        (shared.callback)("serviceFound", info);
    }
}

impl NativeBrowser {
    pub fn new<F>(service_type: &str, domain: Option<&str>, callback: F) -> Result<Self, String>
    where
        F: Fn(&str, ServiceInfo) + Send + Sync + 'static,
    {
        let lib = AvahiLibrary::get()?;

        // Avahi wants the whole `type` as "<subtype>._sub.<base_type>", not
        // the Bonjour "_type._tcp,_subtype" comma form (see compat.c's
        // DNSServiceBrowse, which rewrites it the same way). Multiple
        // subtypes per browse aren't supported either side; use the base.
        let (base_type, subtypes) = split_service_type(service_type);
        let effective_type = match subtypes.as_slice() {
            [only] => format!("{}._sub.{}", only, base_type),
            _ => service_type.to_string(),
        };
        let type_c = CString::new(effective_type).map_err(|e| e.to_string())?;
        let domain_c = match domain {
            Some(d) if !d.is_empty() => Some(CString::new(d).map_err(|e| e.to_string())?),
            _ => None,
        };
        let domain_ptr = domain_c.as_ref().map_or(ptr::null(), |d| d.as_ptr());

        let simple_poll = unsafe { (lib.simple_poll_new)() };
        if simple_poll.is_null() {
            return Err("failed to create avahi poll object".to_string());
        }

        let shared = Arc::new(BrowseShared {
            callback: Arc::new(callback),
            dead: Arc::new(AtomicBool::new(false)),
            client: AtomicUsize::new(0),
            services: Mutex::new(HashMap::new()),
            resolvers: Mutex::new(HashMap::new()),
        });

        let client_ctx = Box::into_raw(Box::new(shared.clone()));
        let mut error: c_int = 0;
        let client = unsafe {
            (lib.client_new)(
                (lib.simple_poll_get)(simple_poll),
                0,
                browse_client_callback,
                client_ctx as *mut c_void,
                &mut error,
            )
        };
        if client.is_null() {
            unsafe {
                drop(Box::from_raw(client_ctx));
                (lib.simple_poll_free)(simple_poll);
            }
            return Err(format!(
                "failed to connect to avahi-daemon: {}",
                lib.error_message(error)
            ));
        }
        shared.client.store(client as usize, Ordering::SeqCst);

        let browser_ctx = Box::into_raw(Box::new(shared.clone()));
        let browser = unsafe {
            (lib.service_browser_new)(
                client,
                AVAHI_IF_UNSPEC,
                AVAHI_PROTO_UNSPEC,
                type_c.as_ptr(),
                domain_ptr,
                0,
                browser_callback,
                browser_ctx as *mut c_void,
            )
        };
        if browser.is_null() {
            let err = unsafe { (lib.client_errno)(client) };
            unsafe {
                drop(Box::from_raw(client_ctx));
                drop(Box::from_raw(browser_ctx));
                (lib.client_free)(client);
                (lib.simple_poll_free)(simple_poll);
            }
            return Err(format!(
                "failed to start avahi service browser: {}",
                lib.error_message(err)
            ));
        }

        let stop_flag = Arc::new(Mutex::new(false));
        let stop_flag_clone = stop_flag.clone();
        let dead_clone = shared.dead.clone();
        let simple_poll_addr = simple_poll as usize;

        let thread = thread::spawn(move || {
            let simple_poll = simple_poll_addr as *mut AvahiSimplePoll;
            loop {
                if *stop_flag_clone.lock().unwrap() || dead_clone.load(Ordering::SeqCst) {
                    break;
                }
                let lib = match AvahiLibrary::get() {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let ret = unsafe { (lib.simple_poll_iterate)(simple_poll, 100) };
                if ret != 0 {
                    break;
                }
            }
        });

        Ok(NativeBrowser {
            client: client as usize,
            simple_poll: simple_poll as usize,
            client_ctx: client_ctx as usize,
            browser_ctx: browser_ctx as usize,
            stop_flag,
            thread: Some(thread),
            shared,
            stopped: false,
        })
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;

        *self.stop_flag.lock().unwrap() = true;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }

        // avahi_client_free() cascades to the browser and every resolver
        // created from this client, per client.h's own docs.
        if let Ok(lib) = AvahiLibrary::get() {
            if self.client != 0 {
                unsafe { (lib.client_free)(self.client as *mut AvahiClient) };
            }
            if self.simple_poll != 0 {
                unsafe { (lib.simple_poll_free)(self.simple_poll as *mut AvahiSimplePoll) };
            }
        }

        if self.client_ctx != 0 {
            unsafe { drop(Box::from_raw(self.client_ctx as *mut Arc<BrowseShared>)) };
        }
        if self.browser_ctx != 0 {
            unsafe { drop(Box::from_raw(self.browser_ctx as *mut Arc<BrowseShared>)) };
        }
        // Only the Rust boxes here: avahi_client_free() above already cascaded
        // the C-side resolvers, so freeing them again would double-free.
        for (_, (_resolver, ctx)) in self.shared.resolvers.lock().unwrap().drain() {
            unsafe { drop(Box::from_raw(ctx as *mut (Arc<BrowseShared>, ServiceKey))) };
        }
    }
}

impl Drop for NativeBrowser {
    fn drop(&mut self) {
        self.stop();
    }
}

// ----------------------------------------------------------------
// Advertise
// ----------------------------------------------------------------

struct AdvertiseShared {
    callback: SharedRegisterCallback,
    dead: Arc<AtomicBool>,
    group_state: AtomicI32,
}

pub struct NativeAdvertisement {
    client: usize,
    simple_poll: usize,
    client_ctx: usize,
    group_ctx: usize,
    stop_flag: Arc<Mutex<bool>>,
    thread: Option<thread::JoinHandle<()>>,
    stopped: bool,
}

unsafe impl Send for NativeAdvertisement {}

unsafe extern "C" fn advertise_client_callback(
    _client: *mut AvahiClient,
    state: AvahiClientState,
    userdata: *mut c_void,
) {
    let shared = unsafe { &*(userdata as *const Arc<AdvertiseShared>) };
    if state == AVAHI_CLIENT_FAILURE && !shared.dead.swap(true, Ordering::SeqCst) {
        invalidate_availability();
        (shared.callback)(
            "error",
            "advertisement lost its connection to the avahi daemon",
        );
    }
}

unsafe extern "C" fn entry_group_callback(
    _group: *mut AvahiEntryGroup,
    state: AvahiEntryGroupState,
    userdata: *mut c_void,
) {
    let shared = unsafe { &*(userdata as *const Arc<AdvertiseShared>) };
    shared.group_state.store(state, Ordering::SeqCst);
    if state == AVAHI_ENTRY_GROUP_FAILURE {
        shared.dead.store(true, Ordering::SeqCst);
    }
}

impl NativeAdvertisement {
    #[allow(clippy::too_many_arguments)]
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
        let lib = AvahiLibrary::get()?;

        let (base_type, subtypes) = split_service_type(service_type);
        let base_type_c = CString::new(base_type).map_err(|e| e.to_string())?;
        // Wants the full "<subtype>._sub.<base_type>" form (RFC 6763 §7.1),
        // not the bare label.
        let subtype_cs: Vec<CString> = subtypes
            .iter()
            .map(|s| CString::new(format!("{}._sub.{}", s, base_type)).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;

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

        let simple_poll = unsafe { (lib.simple_poll_new)() };
        if simple_poll.is_null() {
            return Err("failed to create avahi poll object".to_string());
        }

        let shared = Arc::new(AdvertiseShared {
            callback: Arc::new(callback),
            dead: Arc::new(AtomicBool::new(false)),
            group_state: AtomicI32::new(-1),
        });

        let client_ctx = Box::into_raw(Box::new(shared.clone()));
        let mut error: c_int = 0;
        let client = unsafe {
            (lib.client_new)(
                (lib.simple_poll_get)(simple_poll),
                0,
                advertise_client_callback,
                client_ctx as *mut c_void,
                &mut error,
            )
        };
        if client.is_null() {
            unsafe {
                drop(Box::from_raw(client_ctx));
                (lib.simple_poll_free)(simple_poll);
            }
            return Err(format!(
                "failed to connect to avahi-daemon: {}",
                lib.error_message(error)
            ));
        }

        let group_ctx = Box::into_raw(Box::new(shared.clone()));
        let group = unsafe { (lib.entry_group_new)(client, entry_group_callback, group_ctx as *mut c_void) };
        if group.is_null() {
            let err = unsafe { (lib.client_errno)(client) };
            unsafe {
                drop(Box::from_raw(client_ctx));
                drop(Box::from_raw(group_ctx));
                (lib.client_free)(client);
                (lib.simple_poll_free)(simple_poll);
            }
            return Err(format!(
                "failed to create avahi entry group: {}",
                lib.error_message(err)
            ));
        }

        // RFC 6762 §9 conflict resolution, matching the Bonjour path's
        // "Name (2)" convention. Avahi reports collisions both synchronously
        // from add_service_strlst (known locally) and asynchronously via the
        // group callback after commit() (found by the daemon's probe).
        let mut established_name: Option<String> = None;
        let mut final_error: Option<String> = None;

        'attempts: for attempt in 1..=MAX_NAME_ATTEMPTS {
            let candidate = if attempt == 1 {
                name.to_string()
            } else {
                let candidate = format!("{} ({})", name, attempt);
                if candidate.len() > crate::MAX_LABEL_BYTES {
                    final_error = Some(format!(
                        "service name is {} bytes after renaming, over the {} byte DNS label limit",
                        candidate.len(),
                        crate::MAX_LABEL_BYTES
                    ));
                    break 'attempts;
                }
                candidate
            };
            let candidate_c = match CString::new(candidate.as_str()) {
                Ok(c) => c,
                Err(_) => {
                    final_error = Some("service name contains a NUL byte".to_string());
                    break 'attempts;
                }
            };

            shared.group_state.store(-1, Ordering::SeqCst);

            let txt_list = match txt {
                Some(t) => match txt_to_string_list(lib, t) {
                    Ok(l) => l,
                    Err(e) => {
                        final_error = Some(e);
                        break 'attempts;
                    }
                },
                None => ptr::null_mut(),
            };

            let add_ret = unsafe {
                (lib.entry_group_add_service_strlst)(
                    group,
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    0,
                    candidate_c.as_ptr(),
                    base_type_c.as_ptr(),
                    domain_ptr,
                    host_ptr,
                    port,
                    txt_list,
                )
            };
            if !txt_list.is_null() {
                unsafe { (lib.string_list_free)(txt_list) };
            }

            if add_ret == AVAHI_ERR_COLLISION {
                continue 'attempts;
            }
            if add_ret != AVAHI_OK {
                final_error = Some(lib.error_message(add_ret));
                break 'attempts;
            }

            let mut subtype_failed = false;
            for subtype_c in &subtype_cs {
                let ret = unsafe {
                    (lib.entry_group_add_service_subtype)(
                        group,
                        AVAHI_IF_UNSPEC,
                        AVAHI_PROTO_UNSPEC,
                        0,
                        candidate_c.as_ptr(),
                        base_type_c.as_ptr(),
                        domain_ptr,
                        subtype_c.as_ptr(),
                    )
                };
                if ret != AVAHI_OK {
                    final_error = Some(lib.error_message(ret));
                    subtype_failed = true;
                    break;
                }
            }
            if subtype_failed {
                break 'attempts;
            }

            let commit_ret = unsafe { (lib.entry_group_commit)(group) };
            if commit_ret != AVAHI_OK {
                final_error = Some(lib.error_message(commit_ret));
                break 'attempts;
            }

            let deadline = Instant::now() + ESTABLISH_TIMEOUT;
            let final_state = loop {
                let state = shared.group_state.load(Ordering::SeqCst);
                if state == AVAHI_ENTRY_GROUP_ESTABLISHED
                    || state == AVAHI_ENTRY_GROUP_COLLISION
                    || state == AVAHI_ENTRY_GROUP_FAILURE
                {
                    break state;
                }
                if Instant::now() >= deadline {
                    break -2; // sentinel: timed out
                }
                unsafe { (lib.simple_poll_iterate)(simple_poll, 100) };
            };

            match final_state {
                AVAHI_ENTRY_GROUP_ESTABLISHED => {
                    established_name = Some(candidate);
                    break 'attempts;
                }
                AVAHI_ENTRY_GROUP_COLLISION => {
                    unsafe { (lib.entry_group_reset)(group) };
                    continue 'attempts;
                }
                -2 => {
                    final_error = Some("timed out waiting for avahi to establish the service".to_string());
                    break 'attempts;
                }
                _ => {
                    let err = unsafe { (lib.client_errno)(client) };
                    final_error = Some(lib.error_message(err));
                    break 'attempts;
                }
            }
        }

        let name = match established_name {
            Some(n) => n,
            None => {
                unsafe {
                    drop(Box::from_raw(client_ctx));
                    drop(Box::from_raw(group_ctx));
                    (lib.client_free)(client);
                    (lib.simple_poll_free)(simple_poll);
                }
                return Err(final_error.unwrap_or_else(|| "failed to register service".to_string()));
            }
        };

        let stop_flag = Arc::new(Mutex::new(false));
        let stop_flag_clone = stop_flag.clone();
        let dead_clone = shared.dead.clone();
        let simple_poll_addr = simple_poll as usize;

        let thread = thread::spawn(move || loop {
            if *stop_flag_clone.lock().unwrap() || dead_clone.load(Ordering::SeqCst) {
                break;
            }
            let lib = match AvahiLibrary::get() {
                Ok(l) => l,
                Err(_) => break,
            };
            let ret = unsafe { (lib.simple_poll_iterate)(simple_poll_addr as *mut AvahiSimplePoll, 100) };
            if ret != 0 {
                break;
            }
        });

        // The retry loop above already confirmed ESTABLISHED synchronously,
        // so it's safe to report success immediately rather than waiting for
        // the background thread to observe it independently.
        (shared.callback)("registered", &name);

        Ok(NativeAdvertisement {
            client: client as usize,
            simple_poll: simple_poll as usize,
            client_ctx: client_ctx as usize,
            group_ctx: group_ctx as usize,
            stop_flag,
            thread: Some(thread),
            stopped: false,
        })
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;

        *self.stop_flag.lock().unwrap() = true;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }

        if let Ok(lib) = AvahiLibrary::get() {
            if self.client != 0 {
                unsafe { (lib.client_free)(self.client as *mut AvahiClient) };
            }
            if self.simple_poll != 0 {
                unsafe { (lib.simple_poll_free)(self.simple_poll as *mut AvahiSimplePoll) };
            }
        }

        if self.client_ctx != 0 {
            unsafe { drop(Box::from_raw(self.client_ctx as *mut Arc<AdvertiseShared>)) };
        }
        if self.group_ctx != 0 {
            unsafe { drop(Box::from_raw(self.group_ctx as *mut Arc<AdvertiseShared>)) };
        }
    }
}

impl Drop for NativeAdvertisement {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::mpsc;

    /// Guards the contract that a browse reports every interface an instance
    /// is reachable on. Deduplicating resolvers by (name, type, domain) alone
    /// collapses that to one address, silently — see `BrowseShared::resolvers`.
    ///
    /// Needs a running avahi-daemon and avahi-browse for ground truth, hence
    /// ignored by default. Vacuous on a single-homed host, and says so.
    ///
    ///   cargo test --lib -- --ignored --nocapture multi_homed
    #[test]
    #[ignore = "requires a running avahi-daemon and avahi-utils; run on a multi-homed host"]
    fn multi_homed_browse_reports_every_interface_address() {
        const SERVICE_TYPE: &str = "_dns-sd-selftest._tcp";
        let instance = format!("multihomed-selftest-{}", std::process::id());

        assert!(
            is_available(),
            "no reachable avahi-daemon: this test needs one (and libavahi-client3)"
        );

        let _ad = NativeAdvertisement::new(
            &instance,
            SERVICE_TYPE,
            None,
            None,
            9987,
            None,
            |_event: &str, _msg: &str| {},
        )
        .expect("advertise failed");

        let (tx, rx) = mpsc::channel();
        let want = instance.clone();
        let _browser = NativeBrowser::new(SERVICE_TYPE, None, move |event, info| {
            if event == "serviceFound" && info.name == want {
                let _ = tx.send(info.addresses.clone());
            }
        })
        .expect("browse failed");

        // Collect until the address set stops growing; each interface leg
        // resolves independently, so they trickle in rather than arriving at
        // once.
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut ours: Vec<String> = Vec::new();
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(addrs) => {
                    if addrs.len() > ours.len() {
                        ours = addrs;
                    }
                }
                Err(_) => {
                    if !ours.is_empty() {
                        break;
                    }
                }
            }
        }
        assert!(!ours.is_empty(), "browse never found our own advertisement");

        let theirs = avahi_browse_addresses(SERVICE_TYPE, &instance);
        assert!(
            !theirs.is_empty(),
            "avahi-browse saw no addresses for {instance}; is avahi-utils installed?"
        );

        if theirs.len() == 1 {
            eprintln!(
                "NOTE: this host announced only one address, so the multi-homed \
                 property is untested here. Re-run on a multi-homed host."
            );
        }

        let mut ours_sorted = ours.clone();
        ours_sorted.sort();
        let mut theirs_sorted = theirs.clone();
        theirs_sorted.sort();
        assert_eq!(
            ours_sorted, theirs_sorted,
            "address set disagrees with avahi-browse ground truth: \
             we reported {} address(es), avahi reported {}. A shortfall here \
             usually means resolvers are being deduplicated across interfaces.",
            ours.len(),
            theirs.len()
        );
    }

    /// Ground truth straight from Avahi's own tooling, so the test checks us
    /// against the daemon rather than against our own assumptions.
    fn avahi_browse_addresses(service_type: &str, instance: &str) -> Vec<String> {
        let out = Command::new("avahi-browse")
            .args(["-r", "-p", "-t", service_type])
            .output()
            .expect("avahi-browse not runnable; install avahi-utils to run this test");

        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.starts_with('='))
            .map(|l| l.split(';').collect::<Vec<_>>())
            .filter(|f| f.len() > 7 && f[3] == instance)
            .map(|f| f[7].to_string())
            .filter(|a| !a.is_empty())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}
