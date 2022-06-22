// Jackson Coxson

#[macro_use]
extern crate log;

use std::sync::Arc;

use anyhow::Context;
use tokio::runtime::{self};
use tokio::sync::broadcast;

use crate::config::{Config, PortProtocol};
use crate::events::Bus;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::tcp::TcpVirtualInterface;
use crate::virtual_iface::udp::UdpVirtualInterface;
use crate::virtual_iface::VirtualInterfacePoll;
use crate::wg::WireGuardTunnel;

pub mod config;
pub mod events;
pub mod pcap;
pub mod tunnel;
pub mod virtual_device;
pub mod virtual_iface;
pub mod wg;

pub struct Handle {
    kill_switch: broadcast::Sender<()>,
    tcp_port_pool: TcpPortPool,
    udp_port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
    bus: Bus,
}

impl Handle {
    pub fn get_killer(&self) -> broadcast::Receiver<()> {
        self.kill_switch.subscribe()
    }
    pub fn kill(&self) {
        self.kill_switch.send(()).unwrap();
    }
}

pub async fn start(config: Config) {
    init_logger(&config).unwrap();

    for warning in &config.warnings {
        warn!("{}", warning);
    }

    // Initialize the port pool for each protocol
    let tcp_port_pool = TcpPortPool::new();
    let udp_port_pool = UdpPortPool::new();

    let bus = Bus::default();

    let wg = WireGuardTunnel::new(&config, bus.clone())
        .await
        .with_context(|| "Failed to initialize WireGuard tunnel")
        .unwrap();
    let wg = Arc::new(wg);

    let (kill_switch, _) = broadcast::channel(1);
    let handle = Handle {
        kill_switch,
        tcp_port_pool: tcp_port_pool.clone(),
        udp_port_pool: udp_port_pool.clone(),
        wg: wg.clone(),
        bus: bus.clone(),
    };

    if let Some(pcap_file) = config.pcap_file.clone() {
        // Start packet capture
        let bus = bus.clone();
        let kill_switch = handle.get_killer();
        tokio::spawn(async move { pcap::capture(pcap_file, bus, kill_switch).await });
    }

    {
        // Start routine task for WireGuard
        let wg = wg.clone();
        let kill_switch = handle.get_killer();
        tokio::spawn(async move { wg.routine_task(kill_switch).await });
    }

    {
        // Start consumption task for WireGuard
        let wg = wg.clone();
        let kill_switch = handle.get_killer();
        tokio::spawn(async move { wg.consume_task(kill_switch).await });
    }

    {
        // Start production task for WireGuard
        let wg = wg.clone();
        let kill_switch = handle.get_killer();
        tokio::spawn(async move { wg.produce_task(kill_switch).await });
    }

    if config
        .port_forwards
        .iter()
        .any(|pf| pf.protocol == PortProtocol::Tcp)
    {
        // TCP device
        let bus = bus.clone();
        let device =
            VirtualIpDevice::new(PortProtocol::Tcp, bus.clone(), config.max_transmission_unit);

        // Start TCP Virtual Interface
        let port_forwards = config.port_forwards.clone();
        let iface = TcpVirtualInterface::new(port_forwards, bus, config.source_peer_ip);
        let kill_switch = handle.get_killer();
        tokio::spawn(async move { iface.poll_loop(device, kill_switch).await });
    }

    if config
        .port_forwards
        .iter()
        .any(|pf| pf.protocol == PortProtocol::Udp)
        || config
            .remote_port_forwards
            .iter()
            .any(|pf| pf.protocol == PortProtocol::Udp)
    {
        // UDP device
        let bus = bus.clone();
        let device =
            VirtualIpDevice::new(PortProtocol::Udp, bus.clone(), config.max_transmission_unit);

        // Start UDP Virtual Interface
        let port_forwards = config.port_forwards.clone();
        let remote_port_forwards = config.remote_port_forwards.clone();
        let iface = UdpVirtualInterface::new(
            port_forwards,
            remote_port_forwards,
            bus,
            config.source_peer_ip,
        );
        let kill_switch = handle.get_killer();
        tokio::spawn(async move { iface.poll_loop(device, kill_switch).await });
    }

    {
        let port_forwards = config.port_forwards;
        let source_peer_ip = config.source_peer_ip;

        port_forwards
            .into_iter()
            .map(|pf| {
                (
                    pf,
                    wg.clone(),
                    tcp_port_pool.clone(),
                    udp_port_pool.clone(),
                    bus.clone(),
                    handle.get_killer(),
                )
            })
            .for_each(
                move |(pf, wg, tcp_port_pool, udp_port_pool, bus, kill_switch)| {
                    tokio::spawn(async move {
                        tunnel::port_forward(
                            pf,
                            source_peer_ip,
                            tcp_port_pool,
                            udp_port_pool,
                            wg,
                            bus,
                            kill_switch,
                        )
                        .await
                        .unwrap_or_else(|e| error!("Port-forward failed for {} : {}", pf, e))
                    });
                },
            );
    }

    {
        let remote_port_forwards = config.remote_port_forwards;

        remote_port_forwards
            .into_iter()
            .map(|pf| {
                (
                    pf,
                    wg.clone(),
                    tcp_port_pool.clone(),
                    udp_port_pool.clone(),
                    bus.clone(),
                    handle.get_killer(),
                )
            })
            .for_each(
                move |(pf, wg, tcp_port_pool, udp_port_pool, bus, kill_switch)| {
                    tokio::spawn(async move {
                        tunnel::remote_port_forward(
                            pf,
                            tcp_port_pool,
                            udp_port_pool,
                            wg,
                            bus,
                            kill_switch,
                        )
                        .await
                        .unwrap_or_else(|e| error!("Remote port-forward failed for {} : {}", pf, e))
                    });
                },
            );
    }
    println!("Survived start");

    futures::future::pending().await
}

pub fn blocking_start(config: Config) -> anyhow::Result<(), anyhow::Error> {
    let rt = runtime::Builder::new_multi_thread().enable_all().build()?;
    std::thread::spawn(move || {
        rt.block_on(async {
            start(config).await;
        });
    });

    Ok(())
}

fn init_logger(config: &Config) -> anyhow::Result<()> {
    let mut builder = pretty_env_logger::formatted_timed_builder();
    builder.parse_filters(&config.log);
    builder
        .try_init()
        .with_context(|| "Failed to initialize logger")
}
