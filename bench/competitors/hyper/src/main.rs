//! hyper, one of the servers colibri's is measured against (design §8 step 13g), as
//! `bench/run.sh --competitors` starts it: one thread, on the core run.sh pins it to, answering
//! every request with the answer of colibri's test-only server from memory. It serves h11 and h2
//! on one port, in cleartext or, with `--tls <prefix>`, over TLS with `<prefix>.chain.pem` and
//! `<prefix>.key.pem`, offering h2 and then http/1.1 by ALPN.
//!
//!   colibri-bench-hyper --port <port> [--tls <prefix>]

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{header, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// The answer to every request: what colibri's test-only server sends.
async fn answer(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(b"colibri\n")))
        .expect("a fixed response is valid");
    Ok(response)
}

/// The port, and the prefix of the TLS identity, if any.
fn arguments() -> (u16, Option<String>) {
    let mut port = None;
    let mut tls = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--port" => port = arguments.next().and_then(|value| value.parse().ok()),
            "--tls" => tls = arguments.next(),
            _ => usage(),
        }
    }
    (port.unwrap_or_else(|| usage()), tls)
}

fn usage() -> ! {
    eprintln!("usage: colibri-bench-hyper --port <port> [--tls <prefix>]");
    std::process::exit(2);
}

/// A TLS acceptor over the identity at `prefix`, offering h2 and then http/1.1 (RFC 7301).
fn acceptor(prefix: &str) -> TlsAcceptor {
    let read = |suffix: &str| std::fs::read(format!("{prefix}.{suffix}")).expect("the identity reads");
    let chain_pem = read("chain.pem");
    let key_pem = read("key.pem");
    let chain = rustls_pemfile::certs(&mut chain_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .expect("the chain parses");
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("the key parses")
        .expect("the file holds a key");
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the identity is valid");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

async fn serve(port: u16, tls: Option<TlsAcceptor>) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("the port binds");
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let tls = tls.clone();
        tokio::spawn(async move {
            // Each version on its defaults: the builder reads the h2 preface or an h11 request.
            let builder = auto::Builder::new(TokioExecutor::new());
            let served = match tls {
                None => builder.serve_connection(TokioIo::new(stream), service_fn(answer)).await,
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(secured) => builder.serve_connection(TokioIo::new(secured), service_fn(answer)).await,
                    Err(_) => return,
                },
            };
            let _ = served;
        });
    }
}

fn main() {
    let (port, tls) = arguments();
    let acceptor = tls.as_deref().map(acceptor);
    // One thread, as nginx and h2o run one worker each.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("the runtime starts");
    runtime.block_on(serve(port, acceptor));
}
