//! axum's router served over h3, through quinn and the h3 crate (design §8 step 13f): each
//! connection and each request runs as a task on the one-thread runtime.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use bytes::Bytes;
use tower::ServiceExt;

/// Serves `router` over h3 on UDP port `port`, until the process is stopped.
pub async fn serve(port: u16, prefix: &str, router: Router) {
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
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("the TLS configuration suits QUIC");
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(config, SocketAddr::from((Ipv4Addr::LOCALHOST, port))).expect("the port binds");
    println!("listening on port {}", endpoint.local_addr().expect("the socket has an address").port());
    while let Some(incoming) = endpoint.accept().await {
        let router = router.clone();
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else { return };
            let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await else {
                return;
            };
            while let Ok(Some(resolver)) = h3.accept().await {
                let router = router.clone();
                tokio::spawn(async move {
                    let Ok((request, mut stream)) = resolver.resolve_request().await else { return };
                    let request = request.map(|()| axum::body::Body::empty());
                    let Ok(response) = router.oneshot(request).await;
                    let (parts, body) = response.into_parts();
                    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else { return };
                    if stream.send_response(http::Response::from_parts(parts, ())).await.is_err() {
                        return;
                    }
                    if stream.send_data(bytes).await.is_err() {
                        return;
                    }
                    let _ = stream.finish().await;
                });
            }
        });
    }
}
