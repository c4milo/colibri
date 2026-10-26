//! `server.middleware`: what a middleware of a router returns (decision 127 ruling 5, design §8
//! step 25.5). A middleware is a struct with `on_request`, which the router calls at a request's head,
//! before the route's function: first each middleware of the route table, then each of the route
//! entry's, in table order.
//!
//! `on_request` takes the router's context, the request and the response's writer. It returns `.next`,
//! and the router calls the next middleware, then the route. Or it returns `.answered`: it wrote
//! the response, such as a 401, and the router calls nothing more for the request. An error goes
//! to the route table's `error_handler`, as a route's error does.

/// What a middleware's `on_request` returns.
pub const Next = enum {
    /// The router calls the next middleware, then the route.
    next,
    /// The middleware answered the request, and the router calls nothing more for it.
    answered,
};
