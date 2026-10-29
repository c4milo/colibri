//! axum, a server of colibri's request benchmark (design §8 step 13f), as bench/run.sh --latency
//! starts it: a one-thread tokio runtime, the routes of --routes registered with axum's router,
//! and every route answered with 200 and "ok\n". It serves h11, and h2 in cleartext with prior
//! knowledge, on one port. With --h3 it serves h3 instead, on UDP, through quinn and the h3 crate,
//! over the TLS identity whose <prefix>.chain.pem and <prefix>.key.pem --tls names; each request
//! goes to the same axum router. With --tls alone it serves h2 over TLS on TCP, and h11 to a
//! client that offers no h2 in ALPN, through hyper and tokio-rustls. With --no-gso, quinn sends
//! each datagram in a send of its own, for a path with loss under netem (design §8 step 13i).
//!
//!   colibri-bench-axum --port <port> --routes <routes file> [--h3] [--no-gso] [--tls <prefix>]

mod h3_server;
mod tls_server;

use std::collections::BTreeMap;

use axum::http::header;
use axum::routing::{MethodFilter, MethodRouter};
use axum::Router;

async fn ok() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "ok\n")
}

/// Writes a pattern's ":name" segments as "{name}", which axum reads.
fn braces(path: &str) -> String {
    path.split('/')
        .map(|s| if let Some(name) = s.strip_prefix(':') { format!("{{{name}}}") } else { s.to_string() })
        .collect::<Vec<_>>()
        .join("/")
}

fn filter(method: &str) -> MethodFilter {
    match method {
        "GET" => MethodFilter::GET,
        "POST" => MethodFilter::POST,
        "PUT" => MethodFilter::PUT,
        "DELETE" => MethodFilter::DELETE,
        "PATCH" => MethodFilter::PATCH,
        _ => panic!("unknown method {method}"),
    }
}

fn usage() -> ! {
    eprintln!("usage: colibri-bench-axum --port <port> --routes <routes file> [--h3] [--no-gso] [--tls <prefix>]");
    std::process::exit(2);
}

fn main() {
    let mut port = None;
    let mut routes = None;
    let mut h3 = false;
    let mut segments = true;
    let mut tls = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--port" => port = arguments.next().and_then(|value| value.parse::<u16>().ok()),
            "--routes" => routes = arguments.next(),
            "--h3" => h3 = true,
            "--no-gso" => segments = false,
            "--tls" => tls = arguments.next(),
            _ => usage(),
        }
    }
    let (port, routes) = (port.unwrap_or_else(|| usage()), routes.unwrap_or_else(|| usage()));
    // axum takes one handler for each method of a path, so the routes are grouped by path.
    let mut paths: BTreeMap<String, MethodRouter> = BTreeMap::new();
    for line in std::fs::read_to_string(&routes).expect("the routes read").lines() {
        let (method, path) = line.split_once(' ').expect("a route is \"METHOD /path\"");
        let held = paths.remove(path).unwrap_or_default();
        paths.insert(path.to_string(), held.on(filter(method), ok));
    }
    let mut router = Router::new();
    for (path, methods) in paths {
        router = router.route(&braces(&path), methods);
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("the runtime starts");
    if h3 {
        let prefix = tls.unwrap_or_else(|| usage());
        runtime.block_on(h3_server::serve(port, &prefix, segments, router));
        return;
    }
    if let Some(prefix) = tls {
        runtime.block_on(tls_server::serve(port, &prefix, router));
        return;
    }
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.expect("the port binds");
        println!("listening on port {}", listener.local_addr().expect("the socket has an address").port());
        axum::serve(listener, router).await.expect("the server runs");
    });
}
