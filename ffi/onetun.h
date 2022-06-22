/// Starts the tunnel
/// # Arguments
/// * `pointer` - pointer to the config created with `create_wireguard_config`
/// # Returns
/// * `0` - on success
extern int start_wireguard_tunnel(void*);

/// Creates a port forward and returns the pointer to it on success
/// or NULL on failure.
extern int create_port_forward(char, char, char);

/// Creates a Wireguard configuration and returns the pointer to it on success
/// or NULL on failure.
extern void* create_wireguard_config(const char*, const char*, const char*, const char*);
