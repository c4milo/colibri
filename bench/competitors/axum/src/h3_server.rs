//! axum's router served over h3, through quinn and the h3 crate (design §8 step 13f): each
//! connection and each request runs as a task on the one-thread runtime.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use bytes::Bytes;
use tower::ServiceExt;

/// Serves `router` over h3 on UDP port `port`, until the process is stopped. Without `segments`,
/// quinn sends each datagram in a send of its own, where with it quinn uses UDP_SEGMENT.
pub async fn serve(port: u16, prefix: &str, segments: bool, router: Router) {
    let tls = crate::tls_server::identity(prefix, &[b"h3"]);
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("the TLS configuration suits QUIC");
    let mut transport = quinn::TransportConfig::default();
    transport.enable_segmentation_offload(segments);
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
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
