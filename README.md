# GotaTun

A userspace [WireGuard<sup>®</sup>](https://www.wireguard.com/) implementation, and a fork of [BoringTun](https://github.com/cloudflare/boringtun).

## License

All source code in this repository is subject to the terms of the Mozilla Public License, version 2.0 unless stated otherwise. A copy of this license can be found in the file "LICENSE" or at <https://www.mozilla.org/MPL/2.0/>.

Contributions made prior to March 5, 2026 are licensed under the old BSD 3-clause license. A copy of this license can be found in the file "LICENSE-CLOUDFLARE".

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the MPL-2.0 License, shall be licensed as above, without any additional terms or conditions.

## Building

- Library only: `cargo build --lib --no-default-features --release [--target $(TARGET_TRIPLE)]`
- Executable: `cargo build --bin gotatun --release [--target $(TARGET_TRIPLE)]`

### Installation

By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin gotatun --path .`.

### Nix

To build the executable, simply run `nix build .#gotatun`. The final binary will be located in `result/bin/gotatun`.

## Running

As per the specification, to start a tunnel use:

`gotatun [-f/--foreground] INTERFACE-NAME`

The tunnel can then be configured using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8), as a regular WireGuard tunnel, or any other tool.

It is also possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `gotatun`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=gotatun WG_SUDO=1 wg-quick up CONFIGURATION`

*Please note that `wg-quick` will ignore `WG_QUICK_USERSPACE_IMPLEMENTATION` on Linux if you have the wireguard kernel module installed.*

## Testing

Testing this project has a few requirements:

- `sudo`: required to create tunnels. When you run `cargo test` you'll be prompted for your password.
- Docker: you can install it [here](https://www.docker.com/get-started). If you are on Ubuntu/Debian you can run `apt-get install docker.io`.

## Supported platforms

Target triple                 |Binary|Library|
------------------------------|:----:|------|
x86_64-unknown-linux-gnu      |  ✓   | ✓    |
aarch64-unknown-linux-gnu     |  ✓   | ✓    |
aarch64-apple-darwin          |  ✓   | ✓    |
x86_64-pc-windows-msvc        |  ✓   | ✓    |
x86_64-pc-windows-gnullvm     |  ✓   | ✓    |
aarch64-pc-windows-msvc       |  ✓   | ✓    |
aarch64-pc-windows-gnullvm    |  ✓   | ✓    |
x86_64-linux-android          |      | ✓    |
aarch64-linux-android         |      | ✓    |
aarch64-apple-ios             |      | ✓    |

<sub>Other targets may work, but we only test for these</sub>

### Linux

`x86-64`, and `aarch64` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`gotatun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi gotatun`. sudo is not needed.

### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

The TUN-based Windows CLI requires `--wintun` (or `WINTUN_PATH`) to specify
an absolute path to a trusted `wintun.dll` in a directory protected from
unprivileged writes. It does not search for the DLL by name.

## Userspace HTTP proxy (Windows on Arm64 and Linux)

`gotatun-proxy` uses GotaTun and smoltcp entirely in userspace: no TUN device,
Wintun, or WireGuard for Windows installation is needed. A matching `.5` peer
must be configured on the hub. The native Windows/Arm64 runtime has not yet
been tested on the DevBox.

Keep the private `peer.conf` outside the OneDrive-synced source worktree;
do not commit or sync it. On Windows, store it under
`%LOCALAPPDATA%\GotatunProxy\peer.conf` with access restricted to your user.
Replace the placeholders locally:

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.10.0.5/24

[Peer]
PublicKey = <HUB_PUBLIC_KEY>
PresharedKey = <PEER_PRESHARED_KEY>
Endpoint = <HUB_PUBLIC_IPV4>:52897
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
```

From the source worktree in Visual Studio Developer PowerShell on Windows/Arm64:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA 'gotatun-target'
cargo.exe build --release --locked -p gotatun-proxy --target aarch64-pc-windows-msvc
$config = Join-Path $env:LOCALAPPDATA 'GotatunProxy\peer.conf'
$exe = Join-Path $env:CARGO_TARGET_DIR 'aarch64-pc-windows-msvc\release\gotatun-proxy.exe'
& $exe $config
```

Set each application's HTTP/HTTPS proxy to `http://127.0.0.1:18080` (or
choose another local port with `--port`). Ordinary HTTP and `ws://` upgrades
are forwarded; HTTPS and `wss://` use CONNECT. Destinations must be numeric
IPv4 addresses, and traffic not sent through the proxy remains unaffected.

On Linux, keep the config outside the worktree, run `chmod 600 peer.conf`,
then `cargo run --release -p gotatun-proxy -- peer.conf`.

## UAPI extensions

See [UAPI](./UAPI.md) for extensions to the `wg` configuration protocol.

---

## Audits

Independent security audits have been conducted on the project.
See the [audit](./audits/README.md) directory.

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. GotaTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
