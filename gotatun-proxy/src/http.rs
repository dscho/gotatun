// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//! Forward HTTP requests and upgraded connections through userspace TCP.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::Bytes;
use eyre::Result;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::header::{CONTENT_TYPE, HOST, HeaderValue, UPGRADE};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::TcpStack;

type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Serve a localhost HTTP forward proxy until the listener fails.
pub async fn serve(listener: TcpListener, tcp: TcpStack) -> Result<()> {
    let port = listener.local_addr()?.port();
    loop {
        let (client, _) = listener.accept().await?;
        let tcp = tcp.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let tcp = tcp.clone();
                async move { Ok::<_, Infallible>(forward(request, tcp, port).await) }
            });
            if let Err(error) = server_http1::Builder::new()
                .serve_connection(TokioIo::new(client), service)
                .with_upgrades()
                .await
            {
                tracing::warn!("HTTP proxy client connection failed: {error}");
            }
        });
    }
}

fn destination<B>(request: &Request<B>) -> std::result::Result<SocketAddrV4, &'static str> {
    let uri = request.uri();
    let authority = uri
        .authority()
        .ok_or("HTTP proxy requests need an absolute destination")?;
    let ip = authority
        .host()
        .parse::<Ipv4Addr>()
        .map_err(|_| "Use a numeric WireGuard IPv4 address")?;
    let port = authority.port_u16();
    if authority.as_str().contains(':') && port.is_none() {
        return Err("Invalid destination port");
    }
    let port = if request.method() == Method::CONNECT {
        port.ok_or("CONNECT requires a destination port")?
    } else {
        let scheme = uri
            .scheme_str()
            .ok_or("HTTP proxy requests need a scheme")?;
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("ws") {
            return Err("Use http:// or ws://; TLS requires CONNECT");
        }
        port.unwrap_or(80)
    };
    if port == 0 {
        return Err("Destination port must not be zero");
    }
    Ok(SocketAddrV4::new(ip, port))
}

fn message(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(text.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}

fn empty(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}

async fn forward(mut request: Request<Incoming>, tcp: TcpStack, port: u16) -> Response<ProxyBody> {
    if request.method() == Method::GET
        && request.uri().authority().is_none()
        && request.uri().path() == "/proxy.pac"
    {
        let script = format!(
            concat!(
                "function FindProxyForURL(url, host) {{\n",
                "  if (shExpMatch(host, \"10.10.0.*\")) {{\n",
                "    return \"PROXY 127.0.0.1:{}\";\n",
                "  }}\n",
                "  return \"DIRECT\";\n",
                "}}\n",
            ),
            port
        );
        let mut response = Response::new(
            Full::new(Bytes::from(script))
                .map_err(|never| match never {})
                .boxed(),
        );
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-ns-proxy-autoconfig"),
        );
        return response;
    }

    let destination = match destination(&request) {
        Ok(destination) => destination,
        Err(reason) => return message(StatusCode::BAD_REQUEST, reason),
    };
    let upstream = match tcp.connect(destination).await {
        Ok(upstream) => upstream,
        Err(error) => {
            tracing::warn!("Cannot connect to WireGuard peer {destination}: {error}");
            return message(StatusCode::BAD_GATEWAY, "WireGuard peer unavailable");
        }
    };

    if request.method() == Method::CONNECT {
        tokio::spawn(async move {
            match hyper::upgrade::on(request).await {
                Ok(upgraded) => {
                    let mut client = TokioIo::new(upgraded);
                    let mut upstream = upstream;
                    if let Err(error) =
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        tracing::warn!("CONNECT tunnel to {destination} failed: {error}");
                    }
                }
                Err(error) => tracing::warn!("CONNECT upgrade failed: {error}"),
            }
        });
        return empty(StatusCode::OK);
    }

    request
        .headers_mut()
        .remove(hyper::header::PROXY_AUTHORIZATION);
    request.headers_mut().remove("proxy-connection");
    let authority = request
        .uri()
        .authority()
        .expect("destination has authority");
    if !request.headers().contains_key(HOST) {
        let host = match HeaderValue::from_str(authority.as_str()) {
            Ok(host) => host,
            Err(_) => return message(StatusCode::BAD_REQUEST, "Invalid destination host"),
        };
        request.headers_mut().insert(HOST, host);
    }

    let client_upgrade = if request.headers().contains_key(UPGRADE) {
        Some(hyper::upgrade::on(&mut request))
    } else {
        None
    };
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let uri = match path.parse::<Uri>() {
        Ok(uri) => uri,
        Err(_) => return message(StatusCode::BAD_REQUEST, "Invalid HTTP request path"),
    };
    *request.uri_mut() = uri;

    let (mut sender, connection) = match client_http1::handshake(TokioIo::new(upstream)).await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::warn!("HTTP handshake with {destination} failed: {error}");
            return message(StatusCode::BAD_GATEWAY, "WireGuard peer unavailable");
        }
    };
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            tracing::warn!("HTTP connection to {destination} failed: {error}");
        }
    });

    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!("HTTP request to {destination} failed: {error}");
            return message(StatusCode::BAD_GATEWAY, "WireGuard peer request failed");
        }
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return message(StatusCode::BAD_GATEWAY, "Unexpected protocol upgrade");
        };
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((client, upstream)) => {
                    let mut client = TokioIo::new(client);
                    let mut upstream = TokioIo::new(upstream);
                    if let Err(error) =
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        tracing::warn!("WebSocket tunnel to {destination} failed: {error}");
                    }
                }
                Err(error) => tracing::warn!("WebSocket upgrade failed: {error}"),
            }
        });
    }
    response.map(|body| body.boxed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_http_websockets_and_connect() {
        let http = Request::builder()
            .uri("http://10.10.0.2:8080/path")
            .body(())
            .unwrap();
        assert_eq!(
            destination(&http),
            Ok(SocketAddrV4::new(Ipv4Addr::new(10, 10, 0, 2), 8080))
        );
        let websocket = Request::builder()
            .uri("ws://10.10.0.3/socket")
            .body(())
            .unwrap();
        assert_eq!(
            destination(&websocket),
            Ok(SocketAddrV4::new(Ipv4Addr::new(10, 10, 0, 3), 80))
        );
        let tls = Request::builder()
            .method(Method::CONNECT)
            .uri("10.10.0.4:443")
            .body(())
            .unwrap();
        assert_eq!(
            destination(&tls),
            Ok(SocketAddrV4::new(Ipv4Addr::new(10, 10, 0, 4), 443))
        );
    }

    #[test]
    fn rejects_ambiguous_destinations() {
        for uri in [
            "http://example.com/",
            "https://10.10.0.2/",
            "http://10.10.0.2:bad/",
        ] {
            let request = Request::builder().uri(uri).body(()).unwrap();
            assert!(destination(&request).is_err(), "{uri}");
        }
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("10.10.0.2")
            .body(())
            .unwrap();
        assert!(destination(&request).is_err());
    }
}
