# Decision 129: A route names its parameters, and two routes may name one position differently

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-28, who chose it from the patterns that the API tables showed and then
ruled on this text. Amends decision 122 ruling 5.

The route tables of Stripe, Kubernetes and OpenAI give one parameter position two names in
32 routes: Stripe 21, Kubernetes 9 and OpenAI 2. Stripe's `/v1/customers/{customer}/…`
stands beside `/v1/customers/{id}/…`. Ruling 5 refused such a table
(`parameter_names_differ`), so a program renamed its API's parameters to compile it.

The rulings:
1. The trie keeps one parameter child at a node, and the walk binds each value by its
   position, as before. Each route's entry holds the names of its own pattern's parameters.
   When `match` gives `found`, it writes the names of the entry it chose for the values it
   bound. So `GET /users/:id` and `PUT /users/:user` both compile, at one leaf, and each
   reads its value by its own name.
2. `parameter_names_differ` goes. `parameter_repeated` stays: a pattern that names one
   parameter twice, as Stripe's description does in two routes, is ambiguous for its own
   program.
3. The compiler's check of a route's parameter struct against its pattern (decision 127
   ruling 3) reads the route's own names, as it does now.
4. The cost: `found` writes `path_parameters_max` names at most, 8, which the walk wrote
   before. No other result pays it.

Alternatives that lost:
- Keep ruling 5. A program renames its API's parameters, and its parameter structs no longer
  match the API's own description.
- A trie node for each name. Two routes that differ only by a parameter's name would then
  match one path twice, and the order of decision 122 would have to choose between names.
