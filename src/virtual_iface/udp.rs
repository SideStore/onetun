use anyhow::Context;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

use crate::events::Event;
use crate::{Bus, PortProtocol};
use async_trait::async_trait;
use smoltcp::iface::{InterfaceBuilder, SocketHandle};
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpCidr};
use std::time::Duration;

use crate::config::PortForwardConfig;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};

const MAX_PACKET: usize = 65536;

pub struct UdpVirtualInterface {
    source_peer_ip: IpAddr,
    port_forwards: Vec<PortForwardConfig>,
    remote_port_forwards: Vec<PortForwardConfig>,
    bus: Bus,
}

impl UdpVirtualInterface {
    /// Initialize the parameters for a new virtual interface.
    /// Use the `poll_loop()` future to start the virtual interface poll loop.
    pub fn new(
        port_forwards: Vec<PortForwardConfig>,
        remote_port_forwards: Vec<PortForwardConfig>,
        bus: Bus,
        source_peer_ip: IpAddr,
    ) -> Self {
        Self {
            port_forwards: port_forwards
                .into_iter()
                .filter(|f| matches!(f.protocol, PortProtocol::Udp))
                .collect(),
            remote_port_forwards: remote_port_forwards
                .into_iter()
                .filter(|f| matches!(f.protocol, PortProtocol::Udp))
                .collect(),
            source_peer_ip,
            bus,
        }
    }

    fn new_server_socket(port_forward: PortForwardConfig) -> anyhow::Result<UdpSocket<'static>> {
        static mut UDP_SERVER_RX_META: [UdpPacketMetadata; 0] = [];
        static mut UDP_SERVER_RX_DATA: [u8; 0] = [];
        static mut UDP_SERVER_TX_META: [UdpPacketMetadata; 0] = [];
        static mut UDP_SERVER_TX_DATA: [u8; 0] = [];
        let udp_rx_buffer = UdpSocketBuffer::new(unsafe { &mut UDP_SERVER_RX_META[..] }, unsafe {
            &mut UDP_SERVER_RX_DATA[..]
        });
        let udp_tx_buffer = UdpSocketBuffer::new(unsafe { &mut UDP_SERVER_TX_META[..] }, unsafe {
            &mut UDP_SERVER_TX_DATA[..]
        });
        let mut socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        socket
            .bind((
                IpAddress::from(port_forward.destination.ip()),
                port_forward.destination.port(),
            ))
            .with_context(|| "UDP virtual server socket failed to bind")?;
        Ok(socket)
    }

    fn new_client_socket(
        source_peer_ip: IpAddr,
        client_port: VirtualPort,
    ) -> anyhow::Result<UdpSocket<'static>> {
        let rx_meta = vec![UdpPacketMetadata::EMPTY; 10];
        let tx_meta = vec![UdpPacketMetadata::EMPTY; 10];
        let rx_data = vec![0u8; MAX_PACKET];
        let tx_data = vec![0u8; MAX_PACKET];
        let udp_rx_buffer = UdpSocketBuffer::new(rx_meta, rx_data);
        let udp_tx_buffer = UdpSocketBuffer::new(tx_meta, tx_data);
        let mut socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        socket
            .bind((IpAddress::from(source_peer_ip), client_port.num()))
            .with_context(|| "UDP virtual client failed to bind")?;
        Ok(socket)
    }

    fn addresses(&self) -> Vec<IpCidr> {
        let mut addresses = HashSet::new();
        addresses.insert(IpAddress::from(self.source_peer_ip));
        for config in self.port_forwards.iter() {
            addresses.insert(IpAddress::from(config.destination.ip()));
        }
        addresses
            .into_iter()
            .map(|addr| IpCidr::new(addr, 32))
            .collect()
    }
}

#[async_trait]
impl VirtualInterfacePoll for UdpVirtualInterface {
    async fn poll_loop(self, device: VirtualIpDevice) -> anyhow::Result<()> {
        // Create CIDR block for source peer IP + each port forward IP
        let addresses = self.addresses();

        // Create virtual interface (contains smoltcp state machine)
        let mut iface = InterfaceBuilder::new(device, vec![])
            .ip_addrs(addresses)
            .finalize();

        // Create virtual server for each port forward
        for port_forward in self.port_forwards.iter() {
            let server_socket = UdpVirtualInterface::new_server_socket(*port_forward)?;
            iface.add_socket(server_socket);
        }

        // The next time to poll the interface. Can be None for instant poll.
        let mut next_poll: Option<tokio::time::Instant> = None;

        // Bus endpoint to read events
        let mut endpoint = self.bus.new_endpoint();

        // Maps virtual port to its client socket handle
        let mut port_client_handle_map: HashMap<VirtualPort, SocketHandle> = HashMap::new();

        // Data packets to send from a virtual client
        let mut send_queue: HashMap<VirtualPort, VecDeque<(SocketAddr, Vec<u8>)>> = HashMap::new();

        // Create sockets for remote port forwards
        for remote_port_forward in self.remote_port_forwards.iter() {
            let virtual_port =
                VirtualPort::new(remote_port_forward.source.port(), PortProtocol::Udp);
            let client_socket = UdpVirtualInterface::new_client_socket(
                remote_port_forward.source.ip(),
                virtual_port,
            )?;
            let client_handle = iface.add_socket(client_socket);
            port_client_handle_map.insert(virtual_port, client_handle);
            send_queue.insert(virtual_port, VecDeque::new());
        }

        let mut wake = false;

        loop {
            tokio::select! {
                _ = match (next_poll, wake) {
                    (None, false) => tokio::time::sleep(Duration::MAX),
                    (None, true) => tokio::time::sleep(Duration::ZERO),
                    (Some(until), _) => tokio::time::sleep_until(until),
                } => {
                    let loop_start = smoltcp::time::Instant::now();

                    match iface.poll(loop_start) {
                        Ok(processed) if processed => {
                            trace!("UDP virtual interface polled some packets to be processed");
                        }
                        Err(e) => error!("UDP virtual interface poll error: {:?}", e),
                        _ => {}
                    }

                    for (virtual_port, client_handle) in port_client_handle_map.iter() {
                        let client_socket = iface.get_socket::<UdpSocket>(*client_handle);
                        if client_socket.can_send() {
                            if let Some(send_queue) = send_queue.get_mut(virtual_port) {
                                let to_transfer = send_queue.pop_front();
                                if let Some((destination, data)) = to_transfer {
                                    client_socket
                                        .send_slice(
                                            &data,
                                            (IpAddress::from(destination.ip()), destination.port()).into(),
                                        )
                                        .unwrap_or_else(|e| {
                                            error!(
                                                "[{}] Failed to send data to virtual server: {:?}",
                                                virtual_port, e
                                            );
                                        });
                                }
                            }
                        }
                        if client_socket.can_recv() {
                            match client_socket.recv() {
                                Ok((data, peer)) => {
                                    if !data.is_empty() {
                                        trace!("notifying remote data from peer: {}", peer);
                                        endpoint.send(Event::RemoteData(*virtual_port, data.to_vec()));
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to read from virtual client socket: {:?}", e
                                    );
                                }
                            }
                        }
                    }

                    // The virtual interface determines the next time to poll (this is to reduce unnecessary polls)
                    next_poll = match iface.poll_delay(loop_start) {
                        Some(smoltcp::time::Duration::ZERO) => None,
                        Some(delay) => {
                            trace!("UDP Virtual interface delayed next poll by {}", delay);
                            Some(tokio::time::Instant::now() + Duration::from_millis(delay.total_millis()))
                        },
                        None => None,
                    };
                }
                event = endpoint.recv() => {
                    match event {
                        Event::LocalData(port_forward, virtual_port, data) => {
                            let destination = port_forward.destination;

                            if let Some(send_queue) = send_queue.get_mut(&virtual_port) {
                                // Client socket already exists
                                send_queue.push_back((destination, data));
                            } else {
                                // Client socket does not exist
                                let client_socket = UdpVirtualInterface::new_client_socket(self.source_peer_ip, virtual_port)?;
                                let client_handle = iface.add_socket(client_socket);

                                // Add handle to map
                                port_client_handle_map.insert(virtual_port, client_handle);
                                send_queue.insert(virtual_port, VecDeque::from(vec![(destination, data)]));
                            }
                            next_poll = None;
                            wake = true;
                        }
                        Event::VirtualDeviceFed(protocol) if protocol == PortProtocol::Udp => {
                            next_poll = None;
                            wake = true;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
