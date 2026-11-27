# Decision 128: A route table's walk backs up for a method, as it backs up for a path

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-28, who chose it from three ways and then ruled on this text. Amends
decision 122 rulings 10 and 12.

The owner asked for route tables of well-known APIs, to test the router under load, and for a
fix of each pattern that real APIs use and colibri refuses. Seven tables were built from
published descriptions: Stripe, Kubernetes, OpenAI, and GitHub, Parse, Google+ and the static
table of go-http-routing-benchmark. Ruling 12's `route_hidden` refused 25 routes, 15 of
Stripe's 612 and 10 of OpenAI's 369, and each had one shape: a literal action beside a
parameter route at one node, with other methods. `GET /v1/charges/search` stops the walk of
`POST /v1/charges/search`, so `POST /v1/charges/:charge` can never serve that path. A program
could not write either API as its owner publishes it.

The rulings:
1. When the walk stops at a leaf that does not serve the method, it backs up as it does for a
   path that misses: it tries the parameter child, then the wildcard child, of each level it
   backs up to. The first leaf that serves the method decides (amends ruling 10). The walk
   still tries each child kind of a node once at most (INV-32), so its bound stays.
2. When no leaf that the path reaches serves the method, the result is `method_not_allowed`.
   Its Allow value lists the methods of each leaf that the path reaches, in ruling 11's order,
   because RFC 9110 §15.5.6 asks for the methods of the target resource. Each method of the
   table has a bit, each leaf a mask of its methods, and the walk joins the masks of the
   leaves it reaches. The build writes the Allow value of each mask at compile time, and
   refuses a table whose value is longer than `field_value_len_max` (`allow_too_long`).
3. A table names `route_methods_max` methods at most, which the owner set to 10 on
   2026-10-28: RFC 9110's eight, PATCH and one more token. It then needs 1,024 Allow values
   at most. A table with more does not compile (`methods_too_many`). Beat: 8, which refuses
   a table with each of RFC 9110's methods and PATCH, and 16, whose 65,536 values could take
   megabytes of a binary.
4. `route_hidden` goes (amends ruling 12). A literal still wins over a parameter for a method
   that both serve: that is precedence, not a hidden route. `route_unreachable` stays: a
   route that no request reaches for any method does not compile.
5. The cost falls on a request whose method misses at the first leaf: the walk then reads
   the levels it backs up to. A request that the first leaf serves costs what it costs now.

Alternatives that lost:
- Keep the refusal, and let its message name the routes to rename. Stripe's and OpenAI's APIs
  still could not be written as published.
- An option on a route that makes it reachable for the methods the literal lacks. It is one
  more rule for every program with this shape, and a program that forgets it gets a refusal.
- Go 1.22's ServeMux chooses the most specific pattern of those that match the method and the
  path. That is the behaviour of ruling 1, and colibri keeps its own order of precedence
  (literal, parameter, wildcard), which decision 122 ruled.
