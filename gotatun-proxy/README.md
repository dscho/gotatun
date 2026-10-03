# Userspace HTTP proxy

`gotatun-proxy` participates in an existing WireGuard network as a **joining
peer**. It exposes a localhost HTTP proxy instead of a TUN interface:
applications opt in to the proxy, and other traffic keeps its normal routing.
It forwards HTTP and `ws://` upgrades and uses CONNECT for HTTPS and `wss://`.

The **reachable peer** already has a WireGuard interface and a UDP endpoint
accessible to the joining peer. If it forwards traffic to other peers, it
also acts as a **hub**; both sides are still WireGuard peers. Forwarding
through a hub must already be configured on that peer.

This implementation currently requires an unused joining-peer IPv4 address
in `10.10.0.0/24` with a `/24` mask, `AllowedIPs = 10.10.0.0/24`, a preshared
key, and a numeric IP address and port for the reachable peer's `Endpoint`.
The keepalive interval is 25 seconds. Proxy destinations must be numeric
IPv4 addresses. These are implementation limits, not an example subnet
that can be replaced with an arbitrary one.

## Add the joining peer

### Generate keys

On a trusted Unix machine with `wg` installed, generate a new keypair and
preshared key in a private, uniquely named directory:

```sh
(
  set -e
  umask 077
  cd "$(mktemp -d "$HOME/wg-proxy-peer.XXXXXXXX")"
  wg genkey > joining-peer.key
  wg pubkey < joining-peer.key > joining-peer.pub
  wg genpsk > pair.psk
  printf 'Key files are in %s\n' "$PWD"
)
```

Give `joining-peer.pub` and `pair.psk` to the reachable peer. The joining
peer needs `joining-peer.key`, the same `pair.psk`, and the reachable peer's
public key. Transfer secrets by a trusted method; never commit or sync the
private key, preshared key, or final peer configuration.

### Register the joining peer

For an existing Unix interface managed by `wg-quick`, run the following in
a root Bash shell on the reachable peer. Replace `wg0` if its interface has
a different name. Check both its configuration file and loaded `AllowedIPs`
to ensure the joining peer's chosen IPv4 address is unused:

```bash
interface=wg0
config="/etc/wireguard/$interface.conf"
wg show "$interface" allowed-ips
wg show "$interface" public-key
wg show "$interface" listen-port
```

Use the reachable peer's public key and reachable UDP endpoint in the joining
peer's configuration; its externally reachable port may differ from the
interface's listen port. Back up the file before editing it:

```bash
cp -p -- "$config" "$config.bak.$(date -u +%Y%m%dT%H%M%S%N)"
```

Append this block to `$config`, inserting the values from the key files and
the chosen joining-peer IPv4 address:

```ini
[Peer]
PublicKey = <JOINING_PEER_PUBLIC_KEY>
PresharedKey = <PAIR_PRESHARED_KEY>
AllowedIPs = <JOINING_PEER_IPV4>/32
```

Reload the interface without bringing down existing sessions, then check
that the joining peer appears:

```bash
wg syncconf "$interface" <(wg-quick strip "$interface")
wg show "$interface"
```

### Configure and run the joining peer

Create a private `peer.conf` on the joining peer, outside the source
repository and any synchronized or shared folders. On Unix, set
`umask 077` before writing it:

```ini
[Interface]
PrivateKey = <JOINING_PEER_PRIVATE_KEY>
Address = <JOINING_PEER_IPV4>/24

[Peer]
PublicKey = <REACHABLE_PEER_PUBLIC_KEY>
PresharedKey = <PAIR_PRESHARED_KEY>
Endpoint = <REACHABLE_PEER_IPV4>:<UDP_PORT>
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
```

Use the same IPv4 address and preshared key on both sides. The endpoint must
be a numeric IP address and port, not a hostname. On Unix, make the
configuration owner-only before running the proxy:

```sh
chmod 600 /private/path/to/peer.conf
cargo run --release --locked -p gotatun-proxy -- /private/path/to/peer.conf
```

Run Cargo from the workspace root. On Windows, keep the configuration in a
restricted per-user directory outside synchronized folders, for example
`%LOCALAPPDATA%\GotatunProxy\peer.conf`. From a Developer PowerShell with a
Rust toolchain for the desired native target, build from the workspace root:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA 'gotatun-target'
cargo.exe build --release --locked -p gotatun-proxy
```

After the build succeeds, run the executable:

```powershell
$config = Join-Path $env:LOCALAPPDATA 'GotatunProxy\peer.conf'
$exe = Join-Path $env:CARGO_TARGET_DIR 'release\gotatun-proxy.exe'
& $exe $config
```

If using an explicit Cargo `--target` triple, the executable is instead
under that triple's `release` subdirectory.

The proxy listens on `127.0.0.1:18080` by default; use `--port` to choose
another localhost port. Set the application's HTTP/HTTPS proxy to
`http://127.0.0.1:18080`. Alternatively, set its proxy auto-config URL to
`http://127.0.0.1:18080/proxy.pac` (substitute the chosen `--port`). The PAC
routes `10.10.0.*` hosts through the proxy and other hosts directly. To
verify the proxy, request an existing HTTP service at a numeric IPv4 address
on the WireGuard network:

```sh
curl --verbose --proxy http://127.0.0.1:18080 --noproxy localhost 'http://<SERVICE_PEER_IPV4>:<SERVICE_PORT>/'
```

On Windows, use `curl.exe` instead of `curl`. Confirm that it connects to
the localhost proxy and that `wg show "$interface"` on the reachable peer
reports a handshake and traffic for the joining peer.
