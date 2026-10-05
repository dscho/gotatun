// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! TCP sockets carried by GotaTun and smoltcp entirely in userspace.

/// HTTP forwarding and WebSocket tunneling over the userspace TCP stack.
pub mod http;

use std::collections::{HashMap, HashSet, VecDeque};
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
use smoltcp::socket::{Socket, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, TcpPacket,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

const MTU: usize = 1420;
const PACKET_QUEUE: usize = 128;
const TCP_BUFFER: usize = 16 * 1024;
const TCP_RECV_BUFFER: usize = 1024 * 1024;
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
    listeners: HashMap<u16, SocketHandle>,
    next_port: u16,
    closing: Vec<(SocketHandle, Option<u16>)>,
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
            listeners: HashMap::new(),
            next_port: FIRST_LOCAL_PORT + rand::random::<u16>() % 16384,
            closing: Vec::new(),
        }
    }

    fn listen_for_incoming(&mut self, frame: &[u8]) {
        // smoltcp needs a concrete listener before it polls an incoming SYN.
        let Ok(ip) = Ipv4Packet::new_checked(frame) else {
            return;
        };
        if ip.version() != 4
            || ip.next_header() != IpProtocol::Tcp
            || ip.frag_offset() != 0
            || !self.iface.has_ip_addr(ip.dst_addr())
        {
            return;
        }
        let Ok(segment) = TcpPacket::new_checked(ip.payload()) else {
            return;
        };
        let port = segment.dst_port();
        let local = IpEndpoint::new(ip.dst_addr().into(), port);
        let remote = IpEndpoint::new(ip.src_addr().into(), segment.src_port());
        if port == 0
            || !segment.syn()
            || segment.ack()
            || self.listeners.contains_key(&port)
            || self.sockets.iter().any(|(_, socket)| {
                matches!(socket, Socket::Tcp(socket)
                    if (socket.is_listening() && socket.listen_endpoint().port == port)
                        || (socket.local_endpoint() == Some(local)
                            && socket.remote_endpoint() == Some(remote)))
            })
        {
            return;
        }
        let handle = self.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECV_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        ));
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .listen(port)
            .expect("new socket with nonzero port can listen");
        self.listeners.insert(port, handle);
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
                if let Some(port) = port {
                    self.ports.remove(&port);
                }
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
                tcp::SocketBuffer::new(vec![0; TCP_RECV_BUFFER]),
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
            port: Some(port),
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
        let (frames, delay, accepted) = {
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
            let mut accepted = Vec::new();
            let Core {
                sockets,
                packets,
                listeners,
                ..
            } = &mut *core;
            listeners.retain(|port, handle| {
                if sockets.get::<tcp::Socket>(*handle).is_listening() {
                    if packets.inbound.is_empty() {
                        sockets.remove(*handle);
                        false
                    } else {
                        true
                    }
                } else if sockets.get::<tcp::Socket>(*handle).is_active() {
                    accepted.push((*handle, *port));
                    false
                } else {
                    sockets.remove(*handle);
                    false
                }
            });
            (std::mem::take(&mut packets.outbound), delay, accepted)
        };
        for (handle, port) in accepted {
            let mut virtual_stream = TcpStream {
                core: Arc::clone(&core),
                wake: Arc::clone(&wake),
                handle,
                port: None,
            };
            tokio::spawn(async move {
                let established = tokio::time::timeout(
                    Duration::from_secs(10),
                    poll_fn(|cx| {
                        let mut core = virtual_stream.core.lock();
                        let socket = core.sockets.get_mut::<tcp::Socket>(handle);
                        if socket.may_send() {
                            Poll::Ready(true)
                        } else if socket.is_active() {
                            socket.register_send_waker(cx.waker());
                            Poll::Pending
                        } else {
                            Poll::Ready(false)
                        }
                    }),
                )
                .await;
                match established {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!("Incoming WireGuard TCP connection to port {port} closed");
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            "Incoming WireGuard TCP connection to port {port} timed out: {error}"
                        );
                        virtual_stream
                            .core
                            .lock()
                            .sockets
                            .get_mut::<tcp::Socket>(handle)
                            .abort();
                        virtual_stream.wake.notify_one();
                        return;
                    }
                }
                let mut local =
                    match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
                        Ok(local) => local,
                        Err(error) => {
                            tracing::warn!(
                                "Cannot forward incoming WireGuard TCP to 127.0.0.1:{port}: {error}"
                            );
                            virtual_stream
                                .core
                                .lock()
                                .sockets
                                .get_mut::<tcp::Socket>(handle)
                                .abort();
                            virtual_stream.wake.notify_one();
                            return;
                        }
                    };
                if let Err(error) =
                    tokio::io::copy_bidirectional(&mut virtual_stream, &mut local).await
                {
                    tracing::warn!("Reverse TCP connection to 127.0.0.1:{port} failed: {error}");
                }
            });
        }
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
                let mut core = core.lock();
                core.listen_for_incoming(&packet);
                core.packets.inbound.push_back(packet);
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
    port: Option<u16>,
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
    use eyre::bail;
    use gotatun::device::uapi::UapiServer;
    use gotatun::device::uapi::command::{Get, Response};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    fn listen(stack: &TcpStack, port: u16) -> Result<SocketHandle> {
        let mut core = stack.core.lock();
        let handle = core.sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECV_BUFFER]),
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

    async fn server_read(stack: &TcpStack, handle: SocketHandle) -> Result<Vec<u8>> {
        loop {
            let result = {
                let mut core = stack.core.lock();
                let socket = core.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    let mut data = [0; 1024];
                    let len = socket.recv_slice(&mut data)?;
                    Some(data[..len].to_vec())
                } else if !socket.is_active() && socket.state() != tcp::State::Listen {
                    bail!("Virtual TCP peer closed before sending data");
                } else {
                    None
                }
            };
            if let Some(data) = result {
                stack.wake.notify_one();
                return Ok(data);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    async fn server_read_headers(stack: &TcpStack, handle: SocketHandle) -> Result<String> {
        let mut data = Vec::new();
        while !data.ends_with(b"\r\n\r\n") {
            data.extend_from_slice(&server_read(stack, handle).await?);
            if data.len() > 8192 {
                bail!("HTTP request headers too large");
            }
        }
        Ok(String::from_utf8(data)?)
    }

    async fn server_write(stack: &TcpStack, handle: SocketHandle, data: &[u8]) -> Result<()> {
        let mut sent = 0;
        while sent < data.len() {
            let count = {
                let mut core = stack.core.lock();
                let socket = core.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_send() {
                    socket.send_slice(&data[sent..])?
                } else if !socket.may_send() {
                    bail!("Virtual TCP peer closed before receiving data");
                } else {
                    0
                }
            };
            if count == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            } else {
                sent += count;
                stack.wake.notify_one();
            }
        }
        Ok(())
    }

    async fn read_response_headers(
        reader: &mut BufReader<tokio::net::TcpStream>,
    ) -> Result<String> {
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 {
                bail!("HTTP proxy closed before sending response headers");
            }
            headers.push_str(&line);
            if headers.len() > 8192 {
                bail!("HTTP response headers too large");
            }
            if line == "\r\n" {
                return Ok(headers);
            }
        }
    }

    async fn peers() -> Result<(TcpStack, Tunnel, WgDevice)> {
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

        let client = Tunnel::connect(
            client_address,
            client_key,
            *hub_public.as_bytes(),
            preshared_key,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        )
        .await?;
        Ok((server_stack, client, server))
    }

    #[tokio::test]
    async fn download_over_delayed_tcp_link() -> Result<()> {
        let hub_address = Ipv4Addr::new(10, 10, 0, 1);
        let (client, client_in, client_out, _client_task) =
            TcpStack::new(Ipv4Addr::new(10, 10, 0, 5));
        let (server, server_in, server_out, _server_task) = TcpStack::new(hub_address);
        let relay = |mut source: FromStack, destination: ToStack| {
            tokio::spawn(async move {
                let mut pending = VecDeque::new();
                loop {
                    let deadline = pending.front().map(|(deadline, _)| *deadline);
                    tokio::select! {
                        packet = source.0.recv() => {
                            let Some(packet) = packet else {
                                return Ok::<_, eyre::Report>(());
                            };
                            pending.push_back((
                                tokio::time::Instant::now() + Duration::from_millis(75),
                                packet,
                            ));
                        }
                        _ = tokio::time::sleep_until(
                            deadline.unwrap_or_else(tokio::time::Instant::now)
                        ), if deadline.is_some() => {
                            let (_, packet) = pending.pop_front().expect("packet is due");
                            destination
                                .0
                                .send(packet.into_bytes().as_ref().to_vec())
                                .await?;
                        }
                    }
                }
            })
        };
        let _outbound = relay(client_out, server_in);
        let _inbound = relay(server_out, client_in);

        let handle = {
            let mut core = server.core.lock();
            let handle = core.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0; 1024 * 1024]),
            ));
            core.sockets.get_mut::<tcp::Socket>(handle).listen(8080)?;
            handle
        };
        server.wake.notify_one();
        let mut stream = client.connect(SocketAddrV4::new(hub_address, 8080)).await?;
        stream.write_all(b"start").await?;
        assert_eq!(server_read(&server, handle).await?, b"start");

        let data = vec![42; 1024 * 1024];
        let start = StdInstant::now();
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::try_join!(server_write(&server, handle, &data), async {
                let mut received = vec![0; data.len()];
                stream.read_exact(&mut received).await?;
                assert_eq!(received, data);
                Ok::<_, eyre::Report>(())
            })
        })
        .await??;
        let elapsed = start.elapsed();
        eprintln!(
            "1 MiB download over ~150 ms RTT: {:.0} KiB/s",
            data.len() as f64 / elapsed.as_secs_f64() / 1024.0
        );
        assert!(
            elapsed < Duration::from_secs(6),
            "1 MiB download over ~150 ms RTT took {elapsed:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_over_wireguard_survives_resume_and_multiple_streams() -> Result<()> {
        let (server_stack, client, server) = peers().await?;
        let hub_address = Ipv4Addr::new(10, 10, 0, 1);
        let first = listen(&server_stack, 8080)?;
        let after_resume = listen(&server_stack, 8081)?;
        let concurrent_a = listen(&server_stack, 8082)?;
        let concurrent_b = listen(&server_stack, 8083)?;
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

    #[tokio::test]
    async fn inbound_wireguard_tcp_reaches_localhost() -> Result<()> {
        let (server_stack, client, server) = peers().await?;
        let localhost = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination =
            SocketAddrV4::new(Ipv4Addr::new(10, 10, 0, 5), localhost.local_addr()?.port());

        tokio::time::timeout(Duration::from_secs(5), async {
            let mut first = server_stack.connect(destination).await?;
            let buffer_sizes = {
                let core = client.stack.core.lock();
                core.sockets.iter().find_map(|(_, socket)| match socket {
                    Socket::Tcp(socket)
                        if socket
                            .local_endpoint()
                            .is_some_and(|endpoint| endpoint.port == destination.port()) =>
                    {
                        Some((socket.recv_capacity(), socket.send_capacity()))
                    }
                    _ => None,
                })
            };
            assert_eq!(buffer_sizes, Some((TCP_RECV_BUFFER, TCP_BUFFER)));
            let mut second = server_stack.connect(destination).await?;
            first.write_all(b"one!").await?;
            first.shutdown().await?;
            second.write_all(b"two!").await?;
            second.shutdown().await?;

            for _ in 0..2 {
                let (mut local, _) = localhost.accept().await?;
                let mut data = Vec::new();
                local.read_to_end(&mut data).await?;
                local.write_all(&data).await?;
            }
            let mut echoed = Vec::new();
            first.read_to_end(&mut echoed).await?;
            assert_eq!(echoed, b"one!");
            echoed.clear();
            second.read_to_end(&mut echoed).await?;
            assert_eq!(echoed, b"two!");
            Ok::<_, eyre::Report>(())
        })
        .await??;
        server.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn http_websocket_and_connect_cross_wireguard() -> Result<()> {
        let (server_stack, client, server) = peers().await?;
        let plain = listen(&server_stack, 8090)?;
        let websocket = listen(&server_stack, 8091)?;
        let secure_websocket = listen(&server_stack, 8092)?;
        let upload = listen(&server_stack, 8093)?;

        let proxy_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let _proxy = tokio::spawn(http::serve(proxy_listener, client.tcp()));

        let mut pac = tokio::net::TcpStream::connect(proxy_address).await?;
        pac.write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), pac.read_to_end(&mut response)).await??;
        let response = String::from_utf8(response)?;
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| eyre!("PAC response has no headers"))?;
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
        let headers = headers.to_ascii_lowercase();
        assert!(
            headers.contains("\r\ncontent-type: application/x-ns-proxy-autoconfig"),
            "{headers}"
        );
        assert_eq!(
            body,
            format!(
                concat!(
                    "function FindProxyForURL(url, host) {{\n",
                    "  if (shExpMatch(host, \"10.10.0.*\")) {{\n",
                    "    return \"PROXY 127.0.0.1:{}\";\n",
                    "  }}\n",
                    "  return \"DIRECT\";\n",
                    "}}\n",
                ),
                proxy_address.port()
            )
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                async {
                    let headers = server_read_headers(&server_stack, plain).await?;
                    assert!(
                        headers.starts_with("GET /proxy.pac HTTP/1.1\r\n"),
                        "{headers}"
                    );
                    let headers = headers.to_ascii_lowercase();
                    assert!(!headers.contains("proxy-authorization:"), "{headers}");
                    assert!(!headers.contains("proxy-connection:"), "{headers}");
                    server_write(
                        &server_stack,
                        plain,
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    )
                    .await
                },
                async {
                    let mut socket = tokio::net::TcpStream::connect(proxy_address).await?;
                    socket
                        .write_all(
                            b"GET http://10.10.0.1:8090/proxy.pac HTTP/1.1\r\n\
                              Host: 10.10.0.1:8090\r\nProxy-Authorization: Basic dGVzdA==\r\n\
                              Proxy-Connection: keep-alive\r\nConnection: close\r\n\r\n",
                        )
                        .await?;
                    let mut response = Vec::new();
                    socket.read_to_end(&mut response).await?;
                    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{response:?}");
                    assert!(response.ends_with(b"\r\n\r\nhello"), "{response:?}");
                    Ok::<_, eyre::Report>(())
                }
            )
        })
        .await??;

        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                async {
                    let mut request = Vec::new();
                    let body_start = loop {
                        request.extend_from_slice(&server_read(&server_stack, upload).await?);
                        if request.len() > 8192 {
                            bail!("HTTP upload request too large");
                        }
                        if let Some(offset) =
                            request.windows(4).position(|part| part == b"\r\n\r\n")
                            && request.len() >= offset + 4 + 11
                        {
                            break offset + 4;
                        }
                    };
                    let headers = String::from_utf8(request[..body_start].to_vec())?;
                    assert!(
                        headers.starts_with("POST /upload HTTP/1.1\r\n"),
                        "{headers}"
                    );
                    assert_eq!(&request[body_start..], b"hello world");
                    server_write(
                        &server_stack,
                        upload,
                        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                },
                async {
                    let mut socket = tokio::net::TcpStream::connect(proxy_address).await?;
                    socket
                        .write_all(
                            b"POST http://10.10.0.1:8093/upload HTTP/1.1\r\n\
                              Host: 10.10.0.1:8093\r\nContent-Length: 11\r\n\
                              Connection: close\r\n\r\nhello world",
                        )
                        .await?;
                    let mut response = Vec::new();
                    socket.read_to_end(&mut response).await?;
                    assert!(
                        response.starts_with(b"HTTP/1.1 201 Created\r\n"),
                        "{response:?}"
                    );
                    assert!(response.ends_with(b"\r\n\r\nok"), "{response:?}");
                    Ok::<_, eyre::Report>(())
                }
            )
        })
        .await??;

        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                async {
                    let headers = server_read_headers(&server_stack, websocket).await?;
                    assert!(headers.starts_with("GET /ws HTTP/1.1\r\n"), "{headers}");
                    server_write(
                        &server_stack,
                        websocket,
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
                          Upgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    )
                    .await?;
                    let mut frame = Vec::new();
                    while frame.len() < 8 {
                        frame.extend_from_slice(&server_read(&server_stack, websocket).await?);
                    }
                    assert_eq!(&frame, &[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']);
                    server_write(&server_stack, websocket, &[0x81, 2, b'h', b'i']).await
                },
                async {
                    let socket = tokio::net::TcpStream::connect(proxy_address).await?;
                    let mut client = BufReader::new(socket);
                    client
                        .get_mut()
                        .write_all(
                            b"GET ws://10.10.0.1:8091/ws HTTP/1.1\r\n\
                              Host: 10.10.0.1:8091\r\nConnection: Upgrade\r\n\
                              Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                              Sec-WebSocket-Version: 13\r\n\r\n",
                        )
                        .await?;
                    let headers = read_response_headers(&mut client).await?;
                    assert!(headers.starts_with("HTTP/1.1 101 "), "{headers}");
                    client
                        .get_mut()
                        .write_all(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i'])
                        .await?;
                    let mut echoed = [0; 4];
                    client.read_exact(&mut echoed).await?;
                    assert_eq!(&echoed, &[0x81, 2, b'h', b'i']);
                    Ok::<_, eyre::Report>(())
                }
            )
        })
        .await??;

        let mut invalid = tokio::net::TcpStream::connect(proxy_address).await?;
        invalid
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await?;
        let mut rejected = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), invalid.read_to_end(&mut rejected)).await??;
        assert!(
            rejected.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "{rejected:?}"
        );

        let opaque = b"\x16\x03\x03tls\x00opaque";
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(echo(&server_stack, secure_websocket, opaque), async {
                let socket = tokio::net::TcpStream::connect(proxy_address).await?;
                let mut client = BufReader::new(socket);
                client
                    .get_mut()
                    .write_all(b"CONNECT 10.10.0.1:8092 HTTP/1.1\r\nHost: 10.10.0.1:8092\r\n\r\n")
                    .await?;
                let headers = read_response_headers(&mut client).await?;
                assert!(headers.starts_with("HTTP/1.1 200 "), "{headers}");
                client.get_mut().write_all(opaque).await?;
                let mut echoed = vec![0; opaque.len()];
                client.read_exact(&mut echoed).await?;
                assert_eq!(&echoed, opaque);
                Ok::<_, eyre::Report>(())
            })
        })
        .await??;
        server.stop().await;
        Ok(())
    }
}
