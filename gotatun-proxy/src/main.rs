// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use base64::Engine as _;
use clap::Parser;
use eyre::{Context, Result, bail, eyre};
use gotatun_proxy::{Tunnel, http};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    /// Configuration for the joining WireGuard peer
    config: PathBuf,
    /// Local HTTP proxy port (bound to 127.0.0.1)
    #[clap(long, default_value_t = 18080)]
    port: u16,
}

struct PeerConfig {
    address: Ipv4Addr,
    private_key: [u8; 32],
    hub_public_key: [u8; 32],
    preshared_key: [u8; 32],
    endpoint: SocketAddr,
}

fn decode_key(value: &str, name: &str) -> Result<[u8; 32]> {
    let key = base64::prelude::BASE64_STANDARD
        .decode(value)
        .wrap_err_with(|| format!("{name} is not valid base64"))?;
    key.try_into()
        .map_err(|_| eyre!("{name} must contain 32 bytes"))
}

fn parse_config(input: &str) -> Result<PeerConfig> {
    let mut section = "";
    let mut values = HashMap::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.split('#').next().unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[Interface]" || line == "[Peer]" {
            section = if line == "[Interface]" {
                "Interface"
            } else {
                "Peer"
            };
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| eyre!("Malformed peer config at line {}", index + 1))?;
        let name = name.trim();
        if !matches!(
            (section, name),
            ("Interface", "PrivateKey" | "Address")
                | (
                    "Peer",
                    "PublicKey"
                        | "PresharedKey"
                        | "Endpoint"
                        | "AllowedIPs"
                        | "PersistentKeepalive"
                )
        ) {
            bail!("Unsupported peer setting at line {}", index + 1);
        }
        if values.insert((section, name), value.trim()).is_some() {
            bail!("Duplicate peer setting at line {}", index + 1);
        }
    }
    let get = |section, name| {
        values
            .get(&(section, name))
            .copied()
            .ok_or_else(|| eyre!("Missing {section}.{name}"))
    };
    let address = get("Interface", "Address")?
        .parse::<ipnetwork::Ipv4Network>()
        .wrap_err("Invalid Interface.Address")?;
    if address.prefix() != 24 || address.ip().octets()[..3] != [10, 10, 0] {
        bail!("Interface.Address must be in 10.10.0.0/24");
    }
    if get("Peer", "AllowedIPs")? != "10.10.0.0/24" {
        bail!("Peer.AllowedIPs must be 10.10.0.0/24");
    }
    if let Some(keepalive) = values.get(&("Peer", "PersistentKeepalive"))
        && *keepalive != "25"
    {
        bail!("Peer.PersistentKeepalive must be 25");
    }
    Ok(PeerConfig {
        address: address.ip(),
        private_key: decode_key(get("Interface", "PrivateKey")?, "Interface.PrivateKey")?,
        hub_public_key: decode_key(get("Peer", "PublicKey")?, "Peer.PublicKey")?,
        preshared_key: decode_key(get("Peer", "PresharedKey")?, "Peer.PresharedKey")?,
        endpoint: get("Peer", "Endpoint")?
            .parse()
            .wrap_err("Peer.Endpoint must be a numeric IP address and port")?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .map_err(|error| eyre!("Failed to initialize logging: {error}"))?;
    let args = Args::parse();
    if args.port == 0 {
        bail!("Local HTTP proxy port must not be zero");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&args.config)?.permissions().mode() & 0o077 != 0 {
            bail!(
                "Peer config must be readable only by its owner: {}",
                args.config.display()
            );
        }
    }
    let config = parse_config(&std::fs::read_to_string(&args.config)?)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, args.port))
        .await
        .wrap_err("Failed to bind localhost HTTP proxy")?;
    let mut tunnel = Tunnel::connect(
        config.address,
        config.private_key,
        config.hub_public_key,
        config.preshared_key,
        config.endpoint,
    )
    .await?;
    tracing::info!("HTTP proxy listening on {}", listener.local_addr()?);

    tokio::select! {
        result = http::serve(listener, tunnel.tcp()) => result,
        result = tunnel.wait() => result,
        result = tokio::signal::ctrl_c() => Ok(result?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_peer_config_and_rejects_duplicates() {
        let secret = base64::prelude::BASE64_STANDARD.encode([7u8; 32]);
        let config = format!(
            "[Interface]\nPrivateKey = {secret}\nAddress = 10.10.0.5/24\n\
             [Peer]\nPublicKey = {secret}\nPresharedKey = {secret}\n\
             Endpoint = 127.0.0.1:52897\nAllowedIPs = 10.10.0.0/24\nPersistentKeepalive = 25\n"
        );
        let peer = parse_config(&config).unwrap();
        assert_eq!(peer.address, Ipv4Addr::new(10, 10, 0, 5));
        assert_eq!(peer.private_key, [7; 32]);
        assert_eq!(peer.endpoint.port(), 52897);
        assert!(parse_config(&format!("{config}PresharedKey = {secret}\n")).is_err());
    }
}
