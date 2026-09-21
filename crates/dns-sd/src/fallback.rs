//! Fallback DNS-SD backend using mdns-sd (pure Rust)

use mdns_sd::{DaemonEvent, ServiceDaemon, ServiceEvent, ServiceInfo as MdnsServiceInfo};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// The only domain mDNS serves, in the fully qualified form the native
/// backends report (Bonjour/Avahi hand back `local.`, not `local`).
const DOMAIN: &str = "local.";

/// Normalize a service type into the fully qualified form mdns-sd expects.
///
/// Bonjour spells a subtype `_http._tcp,_printer`; mdns-sd wants
/// `_printer._sub._http._tcp.local.`, so the two are translated here instead of
/// leaving subtypes working on one backend only.
fn normalize_type(service_type: &str) -> Result<String, String> {
    let (base, subtype) = match service_type.split_once(',') {
        Some((base, subs)) => {
            let list: Vec<&str> = subs.split(',').filter(|s| !s.is_empty()).collect();
            if list.len() > 1 {
                return Err(format!(
                    "the mdns-sd fallback backend supports a single subtype, got {} in '{}'",
                    list.len(),
                    service_type
                ));
            }
            (base, list.first().copied())
        }
        None => (service_type, None),
    };

    let base = base.trim_end_matches('.');
    let base = base.strip_suffix(".local").unwrap_or(base);

    Ok(match subtype {
        Some(sub) => format!("{}._sub.{}.{}", sub, base, DOMAIN),
        None => format!("{}.{}", base, DOMAIN),
    })
}

/// Split an mDNS fullname into the instance name and the service type, shaped
/// exactly like the native backend reports them (`_http._tcp.` + `local.`).
///
/// Splitting on '.' would truncate any instance name containing a dot
/// ("My.Service 1.0"), so the known type/domain suffix is stripped instead.
fn split_fullname(fullname: &str, type_domain: &str) -> (String, String) {
    // A subtype browse reports the type as "_printer._sub._http._tcp.local.",
    // while the native backends report the base type for the same service.
    const SUB: &str = "._sub.";
    let base_type_domain = match type_domain.find(SUB) {
        Some(idx) => &type_domain[idx + SUB.len()..],
        None => type_domain,
    };

    let name = fullname
        .strip_suffix(base_type_domain)
        .or_else(|| fullname.strip_suffix(type_domain))
        .and_then(|rest| rest.strip_suffix('.'))
        .unwrap_or_else(|| fullname.split('.').next().unwrap_or(""))
        .to_string();
    let service_type = base_type_domain
        .strip_suffix(DOMAIN)
        .unwrap_or(base_type_domain)
        .to_string();
    (name, service_type)
}

/// Service info (matching native backend)
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

/// Browser handle for fallback backend
pub struct FallbackBrowser {
    daemon: Arc<ServiceDaemon>,
    stop_flag: Arc<Mutex<bool>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FallbackBrowser {
    /// Start browsing for services
    pub fn new<F>(service_type: &str, callback: F) -> Result<Self, String>
    where
        F: Fn(&str, ServiceInfo) + Send + Sync + 'static,
    {
        let daemon = ServiceDaemon::new().map_err(|e| format!("Failed to create daemon: {}", e))?;
        let daemon = Arc::new(daemon);

        let service_type = normalize_type(service_type)?;

        let receiver = daemon
            .browse(&service_type)
            .map_err(|e| format!("Failed to browse: {}", e))?;

        let stop_flag = Arc::new(Mutex::new(false));
        let stop_flag_clone = stop_flag.clone();
        let callback = Arc::new(callback);

        let thread = thread::spawn(move || {
            loop {
                if *stop_flag_clone.lock().unwrap() {
                    break;
                }
                
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => {
                        match event {
                            ServiceEvent::ServiceResolved(resolved) => {
                                let (name, stype) =
                                    split_fullname(resolved.get_fullname(), &resolved.ty_domain);

                                let info = ServiceInfo {
                                    name,
                                    service_type: stype,
                                    domain: DOMAIN.to_string(),
                                    host_name: resolved.get_hostname().to_string(),
                                    addresses: resolved.get_addresses().iter().map(|a| a.to_string()).collect(),
                                    port: resolved.get_port(),
                                    txt: resolved.get_properties().iter()
                                        .map(|p| (p.key().to_string(), p.val_str().to_string()))
                                        .collect(),
                                    ttl: 0,
                                };
                                callback("serviceFound", info);
                            }
                            ServiceEvent::ServiceRemoved(stype, fullname) => {
                                // Must be shaped like the ServiceResolved event above:
                                // the JS layer keys services on name + type + domain and
                                // silently drops a removal that does not match.
                                let (name, stype) = split_fullname(&fullname, &stype);
                                let info = ServiceInfo {
                                    name,
                                    service_type: stype,
                                    domain: DOMAIN.to_string(),
                                    host_name: String::new(),
                                    addresses: vec![],
                                    port: 0,
                                    txt: HashMap::new(),
                                    ttl: 0,
                                };
                                callback("serviceLost", info);
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        // A plain timeout is the normal idle case, but a closed
                        // channel means the mdns-sd daemon is gone: no further
                        // events can arrive, so report it instead of spinning.
                        if receiver.is_disconnected() {
                            callback(
                                "error",
                                ServiceInfo {
                                    name: "browse stopped: the mdns-sd responder shut down"
                                        .to_string(),
                                    service_type: String::new(),
                                    domain: String::new(),
                                    host_name: String::new(),
                                    addresses: vec![],
                                    port: 0,
                                    txt: HashMap::new(),
                                    ttl: 0,
                                },
                            );
                            break;
                        }
                        continue;
                    }
                }
            }
        });

        Ok(FallbackBrowser {
            daemon,
            stop_flag,
            thread: Some(thread),
        })
    }

    /// Stop browsing
    pub fn stop(&mut self) {
        *self.stop_flag.lock().unwrap() = true;
        
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        
        let _ = self.daemon.shutdown();
    }
}

impl Drop for FallbackBrowser {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Advertisement handle for fallback backend
pub struct FallbackAdvertisement {
    daemon: Arc<ServiceDaemon>,
    stop_flag: Arc<Mutex<bool>>,
    fullname: String,
    monitor: Option<thread::JoinHandle<()>>,
}

impl FallbackAdvertisement {
    /// Advertise a service
    pub fn new<F>(
        name: &str,
        service_type: &str,
        host_name: Option<&str>,
        port: u16,
        txt: Option<&HashMap<String, String>>,
        callback: F,
    ) -> Result<Self, String>
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        let daemon = ServiceDaemon::new().map_err(|e| format!("Failed to create daemon: {}", e))?;
        let daemon = Arc::new(daemon);

        let service_type = normalize_type(service_type)?;

        // Host name: caller supplied (already qualified by lib.rs), else this machine's
        let host = match host_name {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => {
                let sys_hostname = hostname::get()
                    .map(|h| h.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "localhost".to_string());
                format!("{}.{}", sys_hostname, DOMAIN)
            }
        };

        // Build properties
        let properties: Vec<(&str, &str)> = txt
            .map(|t| t.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
            .unwrap_or_default();

        // Create service info.
        //
        // The address list is left empty here and filled in by `enable_addr_auto()`:
        // without it the daemon announces SRV/TXT records with no A/AAAA records, so
        // no resolver (including mdns-sd's own browser) ever resolves the service.
        let service_info = MdnsServiceInfo::new(
            &service_type,
            name,
            &host,
            "",  // Addresses are auto-detected below
            port,
            &properties[..],
        )
        .map_err(|e| format!("Failed to create service info: {}", e))?
        .enable_addr_auto();

        let fullname = service_info.get_fullname().to_string();

        // Register service
        daemon
            .register(service_info)
            .map_err(|e| format!("Failed to register: {}", e))?;

        let callback = Arc::new(callback);
        callback("registered", name);

        // Watch the daemon for conflict resolution and failures. Without this a
        // service renamed under RFC 6762 section 9 would keep reporting the name
        // the caller asked for, which is not the name on the network any more.
        let stop_flag = Arc::new(Mutex::new(false));
        let monitor = daemon.monitor().ok().map(|receiver| {
            let stop_flag = stop_flag.clone();
            let callback = callback.clone();
            let base = service_type.trim_end_matches('.').to_string();
            let base_no_domain = base
                .strip_suffix(".local")
                .unwrap_or(&base)
                .to_string();

            let mut reported = String::new();

            thread::spawn(move || loop {
                if *stop_flag.lock().unwrap() {
                    break;
                }
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(DaemonEvent::NameChange(change)) => {
                        let renamed = change.new_name.trim_end_matches('.');
                        let instance = renamed
                            .strip_suffix(&base)
                            .or_else(|| renamed.strip_suffix(&base_no_domain))
                            .and_then(|rest| rest.strip_suffix('.'));
                        // A host name change carries a different suffix; only an
                        // instance rename affects the advertised service name.
                        // The daemon reports the change once per interface;
                        // the caller only cares that the name changed.
                        if let Some(instance) = instance {
                            if instance != reported {
                                reported = instance.to_string();
                                callback("registered", instance);
                            }
                        }
                    }
                    Ok(DaemonEvent::Error(e)) => {
                        callback("error", &format!("mdns-sd responder error: {}", e));
                    }
                    Ok(_) => {}
                    Err(_) => {
                        if receiver.is_disconnected() {
                            break;
                        }
                    }
                }
            })
        });

        Ok(FallbackAdvertisement {
            daemon,
            stop_flag,
            fullname,
            monitor,
        })
    }

    /// Stop advertising
    pub fn stop(&mut self) {
        if !*self.stop_flag.lock().unwrap() {
            *self.stop_flag.lock().unwrap() = true;
            if let Some(monitor) = self.monitor.take() {
                let _ = monitor.join();
            }
            let _ = self.daemon.unregister(&self.fullname);
            let _ = self.daemon.shutdown();
        }
    }
}

impl Drop for FallbackAdvertisement {
    fn drop(&mut self) {
        self.stop();
    }
}
