// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! TCP sockets carried by GotaTun and smoltcp entirely in userspace.

use std::collections::{HashSet, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};

use eyre::{Result, eyre};
use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use gotatun::udp::socket::UdpSocketFactory;
use gotatun::x25519;
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device as PhyDevice, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

const MTU: usize = 1420;
const PACKET_QUEUE: usize = 128;
const TCP_BUFFER: usize = 16 * 1024;
const FIRST_LOCAL_PORT: u16 = 49152;

type WgDevice = Device<(UdpSocketFactory, ToStack, FromStack)>;

/// A WireGuard peer with no operating-system network interface.
pub struct Tunnel {
    stack: TcpStack,
    device: WgDevice,
    network_task: JoinHandle<Result<()>>,
}

impl Tunnel {
    /// Join the existing 10.10.0.0/24 network through the hub.
    pub async fn connect(
        address: Ipv4Addr,
        private_key: [u8; 32],
        hub_public_key: [u8; 32],
        preshared_key: [u8; 32],
        hub_endpoint: SocketAddr,
    ) -> Result<Self> {
        let (stack, to_stack, from_stack, network_task) = TcpStack::new(address);
        let mut peer = Peer::new(x25519::PublicKey::from(hub_public_key))
            .with_endpoint(hub_endpoint)
            .with_allowed_ip("10.10.0.0/24".parse::<ipnetwork::IpNetwork>()?)
            .with_preshared_key(preshared_key);
        peer.keepalive = Some(25);

        let device = DeviceBuilder::new()
            .with_private_key(x25519::StaticSecret::from(private_key))
            .with_ip_pair(to_stack, from_stack)
            .with_default_udp()
            .with_peer(peer)
            .build()
            .await?;

        Ok(Self {
            stack,
            device,
            network_task,
        })
    }

    /// Open TCP connections to other WireGuard peers.
    pub fn tcp(&self) -> TcpStack {
        self.stack.clone()
    }

    /// Wait for either half of the userspace connection to fail.
    pub async fn wait(&mut self) -> Result<()> {
        tokio::select! {
            _ = self.device.wait() => Err(eyre!("WireGuard device stopped unexpectedly")),
            result = &mut self.network_task => {
                result.map_err(|error| eyre!("TCP stack task failed: {error}"))??;
                Err(eyre!("TCP stack stopped unexpectedly"))
            }
        }
    }
}

struct ToStack(mpsc::Sender<Vec<u8>>);
struct FromStack(mpsc::Receiver<Packet<Ip>>);

impl IpSend for ToStack {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.0
            .send(packet.into_bytes().as_ref().to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TCP stack stopped"))
    }
}

impl IpRecv for FromStack {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .0
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "TCP stack stopped"))?;
        Ok(std::iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(MTU as u16)
    }
}

#[derive(Default)]
struct PacketDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

struct Incoming(Vec<u8>);
struct Outgoing<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Incoming {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for Outgoing<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.push_back(frame);
        result
    }
}

impl PhyDevice for PacketDevice {
    type RxToken<'a> = Incoming;
    type TxToken<'a> = Outgoing<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Incoming, Outgoing<'_>)> {
        if self.outbound.len() >= PACKET_QUEUE {
            return None;
        }
        let frame = self.inbound.pop_front()?;
        Some((Incoming(frame), Outgoing(&mut self.outbound)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Outgoing<'_>> {
        if self.outbound.len() >= PACKET_QUEUE {
            None
        } else {
            Some(Outgoing(&mut self.outbound))
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }
}

struct Core {
    iface: Interface,
    sockets: SocketSet<'static>,
    packets: PacketDevice,
    ports: HashSet<u16>,
    next_port: u16,
    closing: Vec<(SocketHandle, u16)>,
}

impl Core {
    fn new(address: Ipv4Addr) -> Self {
        let mut packets = PacketDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut packets, Instant::ZERO);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::from(address), 24))
                .expect("one address fits");
        });

        Self {
            iface,
            sockets: SocketSet::new(vec![]),
            packets,
            ports: HashSet::new(),
            next_port: FIRST_LOCAL_PORT + rand::random::<u16>() % 16384,
            closing: Vec::new(),
        }
    }

    fn allocate_port(&mut self) -> io::Result<u16> {
        for _ in FIRST_LOCAL_PORT..=u16::MAX {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                FIRST_LOCAL_PORT
            } else {
                port + 1
            };
            if self.ports.insert(port) {
                return Ok(port);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no TCP source ports available",
        ))
    }

    fn remove_closed(&mut self) {
        let mut still_closing = Vec::new();
        for (handle, port) in std::mem::take(&mut self.closing) {
            if self.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed {
                self.sockets.remove(handle);
                self.ports.remove(&port);
            } else {
                still_closing.push((handle, port));
            }
        }
        self.closing = still_closing;
    }
}

/// Shared handle for opening TCP streams inside the WireGuard tunnel.
#[derive(Clone)]
pub struct TcpStack {
    core: Arc<Mutex<Core>>,
    wake: Arc<Notify>,
}

impl TcpStack {
    fn new(address: Ipv4Addr) -> (Self, ToStack, FromStack, JoinHandle<Result<()>>) {
        let (to_stack, incoming) = mpsc::channel(PACKET_QUEUE);
        let (outgoing, from_stack) = mpsc::channel(PACKET_QUEUE);
        let stack = Self {
            core: Arc::new(Mutex::new(Core::new(address))),
            wake: Arc::new(Notify::new()),
        };
        let task = tokio::spawn(run_stack(
            Arc::clone(&stack.core),
            Arc::clone(&stack.wake),
            incoming,
            outgoing,
        ));
        (stack, ToStack(to_stack), FromStack(from_stack), task)
    }

    /// Connect to a TCP service using the peer's virtual IPv4 address.
    pub async fn connect(&self, remote: SocketAddrV4) -> io::Result<TcpStream> {
        let (handle, port) = {
            let mut core = self.core.lock();
            let port = core.allocate_port()?;
            let handle = core.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            ));
            let Core { iface, sockets, .. } = &mut *core;
            if let Err(error) =
                sockets
                    .get_mut::<tcp::Socket>(handle)
                    .connect(iface.context(), remote, port)
            {
                sockets.remove(handle);
                core.ports.remove(&port);
                return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, error));
            }
            (handle, port)
        };
        let stream = TcpStream {
            core: Arc::clone(&self.core),
            wake: Arc::clone(&self.wake),
            handle,
            port,
        };
        self.wake.notify_one();
        poll_fn(|cx| {
            let mut core = stream.core.lock();
            let socket = core.sockets.get_mut::<tcp::Socket>(stream.handle);
            if socket.may_send() {
                Poll::Ready(Ok(()))
            } else if socket.is_active() {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "virtual TCP connection failed",
                )))
            }
        })
        .await?;
        Ok(stream)
    }
}

async fn run_stack(
    core: Arc<Mutex<Core>>,
    wake: Arc<Notify>,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Packet<Ip>>,
) -> Result<()> {
    let started = StdInstant::now();
    loop {
        let (frames, delay) = {
            let mut core = core.lock();
            let millis = i64::try_from(started.elapsed().as_millis())
                .map_err(|_| eyre!("TCP clock overflow"))?;
            let now = Instant::from_millis(millis);
            let Core {
                iface,
                sockets,
                packets,
                ..
            } = &mut *core;
            iface.poll(now, packets, sockets);
            let delay = iface
                .poll_delay(now, sockets)
                .map(|duration| Duration::from_micros(duration.total_micros()))
                .unwrap_or(Duration::from_secs(60));
            core.remove_closed();
            (std::mem::take(&mut core.packets.outbound), delay)
        };
        let sent = !frames.is_empty();
        for frame in frames {
            let packet = Packet::copy_from(frame.as_slice()).try_into_ip()?;
            outgoing
                .send(packet)
                .await
                .map_err(|_| eyre!("WireGuard device stopped reading IP packets"))?;
        }
        if sent {
            continue;
        }
        tokio::select! {
            packet = incoming.recv() => {
                let packet = packet.ok_or_else(|| eyre!("WireGuard device stopped sending IP packets"))?;
                core.lock().packets.inbound.push_back(packet);
            }
            _ = wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// An asynchronous TCP stream owned by the userspace stack.
pub struct TcpStream {
    core: Arc<Mutex<Core>>,
    wake: Arc<Notify>,
    handle: SocketHandle,
    port: u16,
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut core = self.core.lock();
        let socket = core.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_recv() {
            let n = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(|error| io::Error::new(io::ErrorKind::ConnectionReset, error))?;
            buf.advance(n);
            drop(core);
            self.wake.notify_one();
            Poll::Ready(Ok(()))
        } else if socket.may_recv() {
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        } else {
            match socket.recv_slice(&mut []) {
                Err(tcp::RecvError::Finished) => Poll::Ready(Ok(())),
                _ => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "virtual TCP connection reset",
                ))),
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut core = self.core.lock();
        let socket = core.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_send() {
            let n = socket
                .send_slice(data)
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
            drop(core);
            self.wake.notify_one();
            Poll::Ready(Ok(n))
        } else if socket.may_send() {
            socket.register_send_waker(cx.waker());
            Poll::Pending
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "virtual TCP connection closed",
            )))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.core
            .lock()
            .sockets
            .get_mut::<tcp::Socket>(self.handle)
            .close();
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut core = self.core.lock();
        core.sockets.get_mut::<tcp::Socket>(self.handle).close();
        core.closing.push((self.handle, self.port));
        drop(core);
        self.wake.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gotatun::device::uapi::UapiServer;
    use gotatun::device::uapi::command::{Get, Response};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn listen(stack: &TcpStack, port: u16) -> Result<SocketHandle> {
        let mut core = stack.core.lock();
        let handle = core.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        ));
        core.sockets.get_mut::<tcp::Socket>(handle).listen(port)?;
        drop(core);
        stack.wake.notify_one();
        Ok(handle)
    }

    async fn echo(stack: &TcpStack, handle: SocketHandle, expected: &[u8]) -> Result<()> {
        let mut received = Vec::new();
        loop {
            let got_data = {
                let mut core = stack.core.lock();
                let socket = core.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    let mut request = [0; 64];
                    let len = socket.recv_slice(&mut request)?;
                    received.extend_from_slice(&request[..len]);
                    assert_eq!(socket.send_slice(&request[..len])?, len);
                    true
                } else {
                    false
                }
            };
            if got_data {
                stack.wake.notify_one();
                if received.len() >= expected.len() {
                    assert_eq!(&received, expected);
                    return Ok(());
                }
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    async fn roundtrip(stack: &TcpStack, hub: Ipv4Addr, port: u16, request: &[u8]) -> Result<()> {
        let mut stream = stack.connect(SocketAddrV4::new(hub, port)).await?;
        stream.write_all(request).await?;
        let mut response = vec![0; request.len()];
        stream.read_exact(&mut response).await?;
        assert_eq!(response, request);
        Ok(())
    }

    #[tokio::test]
    async fn tcp_over_wireguard_survives_resume_and_multiple_streams() -> Result<()> {
        let hub_address = Ipv4Addr::new(10, 10, 0, 1);
        let client_address = Ipv4Addr::new(10, 10, 0, 5);
        let client_key = rand::random::<[u8; 32]>();
        let hub_key = rand::random::<[u8; 32]>();
        let preshared_key = rand::random::<[u8; 32]>();
        let client_public = x25519::PublicKey::from(&x25519::StaticSecret::from(client_key));
        let hub_public = x25519::PublicKey::from(&x25519::StaticSecret::from(hub_key));

        let (server_stack, to_stack, from_stack, _server_task) = TcpStack::new(hub_address);
        let (uapi_client, uapi_server) = UapiServer::new();
        let server = DeviceBuilder::new()
            .with_private_key(x25519::StaticSecret::from(hub_key))
            .with_ip_pair(to_stack, from_stack)
            .with_default_udp()
            .with_uapi(uapi_server)
            .with_peer(
                Peer::new(client_public)
                    .with_allowed_ip("10.10.0.5/32".parse::<ipnetwork::IpNetwork>()?)
                    .with_preshared_key(preshared_key),
            )
            .build()
            .await?;
        let Response::Get(config) = uapi_client.send(Get::default()).await? else {
            return Err(eyre!("expected WireGuard config response"));
        };
        let port = config
            .listen_port
            .filter(|port| *port != 0)
            .ok_or_else(|| eyre!("hub UDP port not assigned"))?;

        let first = listen(&server_stack, 8080)?;
        let after_resume = listen(&server_stack, 8081)?;
        let concurrent_a = listen(&server_stack, 8082)?;
        let concurrent_b = listen(&server_stack, 8083)?;

        let client = Tunnel::connect(
            client_address,
            client_key,
            *hub_public.as_bytes(),
            preshared_key,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        )
        .await?;
        let tcp = client.tcp();

        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                roundtrip(&tcp, hub_address, 8080, b"hello"),
                echo(&server_stack, first, b"hello"),
            )
        })
        .await??;

        client.device.suspend().await;
        client.device.resume().await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                roundtrip(&tcp, hub_address, 8081, b"awake"),
                echo(&server_stack, after_resume, b"awake"),
            )
        })
        .await??;

        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                roundtrip(&tcp, hub_address, 8082, b"red"),
                roundtrip(&tcp, hub_address, 8083, b"blue"),
                echo(&server_stack, concurrent_a, b"red"),
                echo(&server_stack, concurrent_b, b"blue"),
            )
        })
        .await??;
        server.stop().await;
        Ok(())
    }
}
