//! FFI bindings for dns_sd.h (Apple's DNS-SD API)
//! Compatible with both Bonjour and Avahi's libdns_sd

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{c_char, c_void, c_int};
use std::os::raw::c_ushort;

/// Opaque reference to a DNS service
pub type DNSServiceRef = *mut c_void;

/// Flags for DNS-SD operations
pub type DNSServiceFlags = u32;

/// Error codes
pub type DNSServiceErrorType = i32;

/// Interface index (0 = any)
pub type u32_t = u32;

// Error codes
pub const K_DNS_SERVICE_ERR_NO_ERROR: DNSServiceErrorType = 0;
pub const K_DNS_SERVICE_ERR_UNKNOWN: DNSServiceErrorType = -65537;
pub const K_DNS_SERVICE_ERR_NO_SUCH_NAME: DNSServiceErrorType = -65538;
pub const K_DNS_SERVICE_ERR_NO_MEMORY: DNSServiceErrorType = -65539;
pub const K_DNS_SERVICE_ERR_BAD_PARAM: DNSServiceErrorType = -65540;
pub const K_DNS_SERVICE_ERR_BAD_REFERENCE: DNSServiceErrorType = -65541;
pub const K_DNS_SERVICE_ERR_BAD_STATE: DNSServiceErrorType = -65542;
pub const K_DNS_SERVICE_ERR_BAD_FLAGS: DNSServiceErrorType = -65543;
pub const K_DNS_SERVICE_ERR_UNSUPPORTED: DNSServiceErrorType = -65544;
pub const K_DNS_SERVICE_ERR_NOT_INITIALIZED: DNSServiceErrorType = -65545;
pub const K_DNS_SERVICE_ERR_ALREADY_REGISTERED: DNSServiceErrorType = -65547;
pub const K_DNS_SERVICE_ERR_NAME_CONFLICT: DNSServiceErrorType = -65548;
pub const K_DNS_SERVICE_ERR_INVALID: DNSServiceErrorType = -65549;
pub const K_DNS_SERVICE_ERR_FIREWALL: DNSServiceErrorType = -65550;
pub const K_DNS_SERVICE_ERR_INCOMPATIBLE: DNSServiceErrorType = -65551;
pub const K_DNS_SERVICE_ERR_TIMEOUT: DNSServiceErrorType = -65568;

// Flags
pub const K_DNS_SERVICE_FLAGS_ADD: DNSServiceFlags = 0x2;
pub const K_DNS_SERVICE_FLAGS_DEFAULT: DNSServiceFlags = 0x4;
pub const K_DNS_SERVICE_FLAGS_NO_AUTO_RENAME: DNSServiceFlags = 0x8;
pub const K_DNS_SERVICE_FLAGS_SHARED: DNSServiceFlags = 0x10;
pub const K_DNS_SERVICE_FLAGS_UNIQUE: DNSServiceFlags = 0x20;
pub const K_DNS_SERVICE_FLAGS_BROWSE_DOMAINS: DNSServiceFlags = 0x40;
pub const K_DNS_SERVICE_FLAGS_REGISTRATION_DOMAINS: DNSServiceFlags = 0x80;
pub const K_DNS_SERVICE_FLAGS_MORE_COMING: DNSServiceFlags = 0x1;

// Service Types
pub const K_DNS_SERVICE_TYPE_A: u16 = 1;
pub const K_DNS_SERVICE_TYPE_AAAA: u16 = 28;

/// TXT record reference
pub type TXTRecordRef = [u8; 16]; // Opaque, 16 bytes should be enough

/// Browse callback type
pub type DNSServiceBrowseReply = Option<
    unsafe extern "C" fn(
        sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32_t,
        error_code: DNSServiceErrorType,
        service_name: *const c_char,
        reg_type: *const c_char,
        reply_domain: *const c_char,
        context: *mut c_void,
    ),
>;

/// Resolve callback type
pub type DNSServiceResolveReply = Option<
    unsafe extern "C" fn(
        sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32_t,
        error_code: DNSServiceErrorType,
        fullname: *const c_char,
        hosttarget: *const c_char,
        port: c_ushort, // network byte order
        txt_len: c_ushort,
        txt_record: *const c_char,
        context: *mut c_void,
    ),
>;

/// Register callback type
pub type DNSServiceRegisterReply = Option<
    unsafe extern "C" fn(
        sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        error_code: DNSServiceErrorType,
        name: *const c_char,
        reg_type: *const c_char,
        domain: *const c_char,
        context: *mut c_void,
    ),
>;

/// GetAddrInfo callback type
pub type DNSServiceGetAddrInfoReply = Option<
    unsafe extern "C" fn(
        sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32_t,
        error_code: DNSServiceErrorType,
        hostname: *const c_char,
        address: *const libc::sockaddr,
        ttl: u32_t,
        context: *mut c_void,
    ),
>;

/// QueryRecord callback type
pub type DNSServiceQueryRecordReply = Option<
    unsafe extern "C" fn(
        sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32_t,
        error_code: DNSServiceErrorType,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32_t,
        context: *mut c_void,
    ),
>;

/// Function pointer types for dynamic loading
pub type FnDNSServiceBrowse = unsafe extern "C" fn(
    sd_ref: *mut DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32_t,
    reg_type: *const c_char,
    domain: *const c_char,
    callback: DNSServiceBrowseReply,
    context: *mut c_void,
) -> DNSServiceErrorType;

pub type FnDNSServiceResolve = unsafe extern "C" fn(
    sd_ref: *mut DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32_t,
    name: *const c_char,
    reg_type: *const c_char,
    domain: *const c_char,
    callback: DNSServiceResolveReply,
    context: *mut c_void,
) -> DNSServiceErrorType;

pub type FnDNSServiceRegister = unsafe extern "C" fn(
    sd_ref: *mut DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32_t,
    name: *const c_char,
    reg_type: *const c_char,
    domain: *const c_char,
    host: *const c_char,
    port: c_ushort, // network byte order
    txt_len: c_ushort,
    txt_record: *const c_void,
    callback: DNSServiceRegisterReply,
    context: *mut c_void,
) -> DNSServiceErrorType;

pub type FnDNSServiceGetAddrInfo = unsafe extern "C" fn(
    sd_ref: *mut DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32_t,
    protocol: u32_t,
    hostname: *const c_char,
    callback: DNSServiceGetAddrInfoReply,
    context: *mut c_void,
) -> DNSServiceErrorType;

pub type FnDNSServiceQueryRecord = unsafe extern "C" fn(
    sd_ref: *mut DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32_t,
    fullname: *const c_char,
    rrtype: u16,
    rrclass: u16,
    callback: DNSServiceQueryRecordReply,
    context: *mut c_void,
) -> DNSServiceErrorType;

pub type FnDNSServiceRefSockFD = unsafe extern "C" fn(sd_ref: DNSServiceRef) -> c_int;

pub type FnDNSServiceProcessResult = unsafe extern "C" fn(sd_ref: DNSServiceRef) -> DNSServiceErrorType;

pub type FnDNSServiceRefDeallocate = unsafe extern "C" fn(sd_ref: DNSServiceRef);

// TXT record functions
pub type FnTXTRecordCreate = unsafe extern "C" fn(
    txt_record: *mut TXTRecordRef,
    buffer_len: c_ushort,
    buffer: *mut c_void,
);

pub type FnTXTRecordDeallocate = unsafe extern "C" fn(txt_record: *mut TXTRecordRef);

pub type FnTXTRecordSetValue = unsafe extern "C" fn(
    txt_record: *mut TXTRecordRef,
    key: *const c_char,
    value_size: u8,
    value: *const c_void,
) -> DNSServiceErrorType;

pub type FnTXTRecordGetLength = unsafe extern "C" fn(txt_record: *const TXTRecordRef) -> c_ushort;

pub type FnTXTRecordGetBytesPtr = unsafe extern "C" fn(txt_record: *const TXTRecordRef) -> *const c_void;

/// Library path based on platform
pub fn get_library_path() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "libdns_sd.so.1"
    }
    #[cfg(target_os = "macos")]
    {
        "/usr/lib/libSystem.B.dylib"
    }
    #[cfg(target_os = "windows")]
    {
        "dnssd.dll"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "libdns_sd.so"
    }
}

/// Convert DNSServiceErrorType to Result
pub fn check_error(err: DNSServiceErrorType) -> Result<(), String> {
    if err == K_DNS_SERVICE_ERR_NO_ERROR {
        Ok(())
    } else {
        Err(format!("DNS-SD error: {}", err))
    }
}
