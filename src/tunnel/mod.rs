use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::broadcast;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::events::Bus;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::wg::WireGuardTunnel;

pub mod tcp;
pub mod udp;

pub async fn port_forward(
    port_forward: PortForwardConfig,
    source_peer_ip: IpAddr,
    tcp_port_pool: TcpPortPool,
    udp_port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
    bus: Bus,
    mut kill_switch: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    info!(
        "Tunneling {} [{}]->[{}] (via [{}] as peer {})",
        port_forward.protocol,
        port_forward.source,
        port_forward.destination,
        &wg.endpoint,
        source_peer_ip
    );

    match port_forward.protocol {
        PortProtocol::Tcp => {
            tokio::select! {
                x = tcp::tcp_proxy_server(port_forward, tcp_port_pool, bus) => x,
                _ = kill_switch.recv() => {
                    info!("Port forwarder has been murdered");
                    Ok(())
                }
            }
        }
        PortProtocol::Udp => {
            tokio::select! {
                x = udp::udp_proxy_server(port_forward, udp_port_pool, bus) => x,
                _ = kill_switch.recv() => {
                    info!("Port forwarder has been murdered");
                    Ok(())
                }
            }
        }
    }
}

pub async fn remote_port_forward(
    port_forward: PortForwardConfig,
    _tcp_port_pool: TcpPortPool,
    udp_port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
    bus: Bus,
    mut kill_switch: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    info!(
        "Remote Tunneling {} [{}]<-[{}] (via [{}])",
        port_forward.protocol, port_forward.destination, port_forward.source, &wg.endpoint,
    );

    match port_forward.protocol {
        PortProtocol::Tcp => Ok(()), // TODO: Remote TCP forwarding
        PortProtocol::Udp => {
            tokio::select! {
                x = udp::udp_proxy_server(port_forward, udp_port_pool, bus) => x,
                _ = kill_switch.recv() => {
                    info!("Port forwarder has been murdered");
                    Ok(())
                }
            }
        }
    }
}
