//! axum's router served over TLS on TCP (design §8 step 13f): h2 to a client that offers it in
//! ALPN and h11 otherwise, through hyper's connection builder over tokio-rustls. Each connection
//! runs as a task on the one-thread runtime.

use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;

/// The TLS 1.3 configuration over the identity whose <prefix>.chain.pem and <prefix>.key.pem
/// hold the chain and the key, offering `alpn` in turn.
pub fn identity(prefix: &str, alpn: &[&[u8]]) -> rustls::ServerConfig {
    let read = |suffix: &str| std::fs::read(format!("{prefix}.{suffix}")).expect("the identity reads");
    let chain = rustls_pemfile::certs(&mut read("chain.pem").as_slice())
        .collect::<Result<Vec<_>, _>>()
        .expect("the chain parses");
    let key = rustls_pemfile::private_key(&mut read("key.pem").as_slice())
        .expect("the key parses")
        .expect("the file holds a key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is offered")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the identity is valid");
    tls.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    tls
}

/// Serves `router` over TLS on TCP port `port`, until the process is stopped.
pub async fn serve(port: u16, prefix: &str, router: Router) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(identity(prefix, &[b"h2", b"http/1.1"])));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.expect("the port binds");
    println!("listening on port {}", listener.local_addr().expect("the socket has an address").port());
    loop {
        let Ok((socket, _)) = listener.accept().await else { continue };
        let _ = socket.set_nodelay(true);
        let (acceptor, router) = (acceptor.clone(), router.clone());
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(socket).await else { return };
            let service = TowerToHyperService::new(router);
            let _ = Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service).await;
        });
    }
}
