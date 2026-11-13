//! `server.middleware`: what a middleware of a router returns (decision 127 ruling 5, design §8
//! step 25.5). A middleware is a struct with `on_request`, which the router calls at a request's head,
//! before the route's function: first each middleware of the route table, then each of the route
//! entry's, in table order.
//!
//! `on_request` takes the router's context, the request context, the request and the response
//! (decision 163). It returns `.next`, and the router calls the next middleware, then the
//! route. Or it returns `.answered`: it wrote the response, such as a 401, and the router calls
//! nothing more for the request. An error goes to the route table's `error_handler`, as a route's
//! error does.
//!
//! Each hook of a middleware takes the request context, a `*server.RequestContext`, after the
//! router's context. Its `values` are the request's own: what a middleware writes there at the
//! head, the route and each later hook of the request read.

/// What a middleware's `on_request` returns.
pub const Next = enum {
    /// The router calls the next middleware, then the route.
    next,
    /// The middleware answered the request, and the router calls nothing more for it.
    answered,
};
