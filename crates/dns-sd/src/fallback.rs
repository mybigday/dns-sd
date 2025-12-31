//! Fallback DNS-SD backend using mdns-sd (pure Rust)

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo as MdnsServiceInfo};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

        // Normalize service type to include .local. if needed
        let service_type = if service_type.ends_with(".local.") {
            service_type.to_string()
        } else if service_type.ends_with('.') {
            format!("{}local.", service_type)
        } else {
            format!("{}.local.", service_type)
        };

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
                                // Extract service name from fullname
                                let fullname = resolved.get_fullname();
                                let name = fullname.split('.').next().unwrap_or("").to_string();
                                
                                // Get service type from the fullname (e.g., "_http._tcp.local.")
                                let parts: Vec<&str> = fullname.split('.').collect();
                                let stype = if parts.len() >= 3 {
                                    format!("{}.{}", parts[1], parts[2])
                                } else {
                                    String::new()
                                };

                                let info = ServiceInfo {
                                    name,
                                    service_type: stype,
                                    domain: "local".to_string(),
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
                                let name = fullname.split('.').next().unwrap_or("").to_string();
                                let info = ServiceInfo {
                                    name,
                                    service_type: stype.to_string(),
                                    domain: "local".to_string(),
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
                        // Timeout or disconnected - continue or break based on stop flag
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
}

impl FallbackAdvertisement {
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
        let daemon = ServiceDaemon::new().map_err(|e| format!("Failed to create daemon: {}", e))?;
        let daemon = Arc::new(daemon);

        // Normalize service type
        let service_type = if service_type.ends_with(".local.") {
            service_type.to_string()
        } else if service_type.ends_with('.') {
            format!("{}local.", service_type)
        } else {
            format!("{}.local.", service_type)
        };

        // Get hostname
        let sys_hostname = hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "localhost".to_string());
        let host = format!("{}.local.", sys_hostname);

        // Build properties
        let properties: Vec<(&str, &str)> = txt
            .map(|t| t.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
            .unwrap_or_default();

        // Create service info
        let service_info = MdnsServiceInfo::new(
            &service_type,
            name,
            &host,
            "",  // Use default addresses
            port,
            &properties[..],
        ).map_err(|e| format!("Failed to create service info: {}", e))?;

        let fullname = service_info.get_fullname().to_string();

        // Register service
        daemon
            .register(service_info)
            .map_err(|e| format!("Failed to register: {}", e))?;

        callback("registered", name);

        Ok(FallbackAdvertisement {
            daemon,
            stop_flag: Arc::new(Mutex::new(false)),
            fullname,
        })
    }

    /// Stop advertising
    pub fn stop(&mut self) {
        if !*self.stop_flag.lock().unwrap() {
            *self.stop_flag.lock().unwrap() = true;
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
