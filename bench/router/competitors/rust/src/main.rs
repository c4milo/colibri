//! The Rust routers of colibri's router benchmark: matchit, under axum, and actix-router. Each
//! registers the routes of ../github_routes.txt, then matches every route's path, the given number
//! of rounds, and prints the nanoseconds of one match.
//!
//!     router-bench <matchit|actix> <routes file> <rounds>
use std::time::Instant;

/// The methods of the routes, so a match picks its router by an index and hashes nothing.
const METHODS: [&str; 4] = ["GET", "POST", "PUT", "DELETE"];

fn method_index(method: &str) -> usize {
    match method {
        "GET" => 0,
        "POST" => 1,
        "PUT" => 2,
        "DELETE" => 3,
        _ => panic!("unknown method {method}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds: usize = args[3].parse().unwrap();
    let routes: Vec<(usize, String)> = std::fs::read_to_string(&args[2])
        .unwrap()
        .lines()
        .map(|line| {
            let mut parts = line.split_whitespace();
            (method_index(parts.next().unwrap()), parts.next().unwrap().to_string())
        })
        .collect();
    let _ = METHODS;
    let found = match args[1].as_str() {
        "matchit" => run_matchit(&routes, rounds),
        "actix" => run_actix(&routes, rounds),
        _ => panic!("unknown router"),
    };
    let _ = found;
}

/// Writes a pattern's ":name" segments as "{name}", which both routers read.
fn braces(path: &str) -> String {
    path.split('/')
        .map(|s| if let Some(name) = s.strip_prefix(':') { format!("{{{name}}}") } else { s.to_string() })
        .collect::<Vec<_>>()
        .join("/")
}

fn report(name: &str, rounds: usize, routes: usize, found: usize, start: Instant) -> usize {
    let matches = rounds * routes;
    let ns = start.elapsed().as_nanos() as f64 / matches.max(1) as f64;
    println!("{name} matches={matches} found={found} ns_per_match={ns:.1}");
    found
}

fn run_matchit(routes: &[(usize, String)], rounds: usize) -> usize {
    let mut routers: Vec<matchit::Router<usize>> = (0..METHODS.len()).map(|_| matchit::Router::new()).collect();
    for (index, (method, path)) in routes.iter().enumerate() {
        routers[*method].insert(braces(path), index).unwrap();
    }
    for (method, path) in routes {
        assert!(routers[*method].at(path).is_ok(), "no route for {path}");
    }
    let start = Instant::now();
    let mut found = 0;
    for _ in 0..rounds {
        for (method, path) in routes {
            if let Ok(matched) = routers[*method].at(std::hint::black_box(path)) {
                std::hint::black_box(&matched.params);
                found += 1;
            }
        }
    }
    report("matchit", rounds, routes.len(), found, start)
}

fn run_actix(routes: &[(usize, String)], rounds: usize) -> usize {
    let mut builders: Vec<actix_router::RouterBuilder<usize>> = (0..METHODS.len()).map(|_| actix_router::Router::build()).collect();
    for (index, (method, path)) in routes.iter().enumerate() {
        builders[*method].path(braces(path).as_str(), index);
    }
    let routers: Vec<actix_router::Router<usize>> = builders.into_iter().map(|b| b.finish()).collect();
    for (method, path) in routes {
        let mut target = actix_router::Path::new(path.as_str());
        assert!(routers[*method].recognize(&mut target).is_some(), "no route for {path}");
    }
    let start = Instant::now();
    let mut found = 0;
    for _ in 0..rounds {
        for (method, path) in routes {
            let mut target = actix_router::Path::new(std::hint::black_box(path.as_str()));
            if routers[*method].recognize(&mut target).is_some() {
                std::hint::black_box(&target);
                found += 1;
            }
        }
    }
    report("actix", rounds, routes.len(), found, start)
}
