use onetun::{self, config, Handle};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

use libc::{c_char, c_void};
use std::ffi::CStr;

#[no_mangle]
pub extern "C" fn hello_from_rust() {
    println!("Hello from Rust!");
}

/// Starts the tunnel
/// # Arguments
/// * `pointer` - pointer to the config created with `create_wireguard_config`
/// # Returns
/// * The handle to the tunnel on success
#[no_mangle]
pub extern "C" fn start_wireguard_tunnel(pointer: *mut config::Config) -> *mut c_void {
    // Ensure the pointer is valid
    let config: Box<config::Config> = unsafe { Box::from_raw(pointer) };

    let handle = match onetun::blocking_start(*config) {
        Ok(h) => h,
        Err(e) => {
            return std::ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(handle)) as *mut c_void
}

/// Kills the tunnel
/// # Arguments
/// * `pointer` - pointer to the handle created with `start_wireguard_tunnel`
#[no_mangle]
pub extern "C" fn kill_wireguard_tunnel(pointer: *mut Handle) {
    // Ensure the pointer is valid
    let handle: Box<Handle> = unsafe { Box::from_raw(pointer) };

    (*handle).kill()
}

/// Creates a port forward and returns the pointer to it on success
/// or NULL on failure.
#[no_mangle]
pub extern "C" fn create_port_forward(
    source: *const c_char,
    destination: *const c_char,
    protocol: *const c_char,
) -> *mut c_void {
    // Check to make sure the pointers aren't null
    if source.is_null() || destination.is_null() || protocol.is_null() {
        return std::ptr::null_mut();
    }

    // Grab them pointers
    let source = unsafe { CStr::from_ptr(source as *mut _) };
    let destination = unsafe { CStr::from_ptr(destination as *mut _) };
    let protocol = unsafe { CStr::from_ptr(protocol as *mut _) };

    // Convert the CStrings to Rust strings
    let source = match source.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let destination = match destination.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let protocol = match protocol.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create socket addresss from the strings
    let source = match SocketAddr::from_str(source) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let destination = match SocketAddr::from_str(destination) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let protocol: config::PortProtocol = match protocol.to_uppercase().as_str() {
        "TCP" => config::PortProtocol::Tcp,
        "UDP" => config::PortProtocol::Udp,
        _ => return std::ptr::null_mut(),
    };

    // Create the port forward
    let port_forward = config::PortForwardConfig::new(source, destination, protocol);

    // Return the pointer to the port forward
    Box::into_raw(Box::new(port_forward)) as *mut c_void
}

/// Creates a Wireguard configuration and returns the pointer to it on success
/// or NULL on failure.
#[no_mangle]
pub extern "C" fn create_wireguard_config(
    endpoint: *const c_char,
    assigned_ip: *const c_char,
    public_key: *const c_char,
    private_key: *const c_char,
) -> *mut c_void {
    // Check to make sure the pointers aren't null
    if endpoint.is_null() || assigned_ip.is_null() || public_key.is_null() || private_key.is_null()
    {
        return std::ptr::null_mut();
    }

    // Grab them pointers
    let endpoint = unsafe { CStr::from_ptr(endpoint as *mut _) };
    let assigned_ip = unsafe { CStr::from_ptr(assigned_ip as *mut _) };
    let public_key = unsafe { CStr::from_ptr(public_key as *mut _) };
    let private_key = unsafe { CStr::from_ptr(private_key as *mut _) };

    // Convert the CStrings to Rust strings
    let endpoint = match endpoint.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let assigned_ip = match assigned_ip.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let public_key = match public_key.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let private_key = match private_key.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Convert endpoint to a SocketAddr
    let endpoint = match SocketAddr::from_str(endpoint) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Convert assigned_ip to an IpAddr
    let assigned_ip = match IpAddr::from_str(assigned_ip) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create the wireguard config
    let wireguard_config = match config::Config::new(
        vec![],
        vec![],
        public_key,
        private_key,
        endpoint,
        assigned_ip,
        None,
        None,
        None,
        None,
    ) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Return the pointer to the wireguard config
    Box::into_raw(Box::new(wireguard_config)) as *mut c_void
}
