# Decision 162: colibri exports nothing of chapulin, and its object file for TLS over TCP holds JWS and SCRAM

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-11, for design §8 step 49. Stompy's proxy calls chapulin for its TLS
and its login checks, and connect-zig checks JSON Web Signatures with chapulin. A program links one
copy of chapulin's object file, and colibri's build compiles it (decision 94).
1. colibri exports no chapulin module, under no name ("Colibri shouldn't leak chapulin").
2. A program that calls chapulin names chapulin in its own `build.zig.zon`, at the commit
   colibri pins. It asks for the object with the same options and the same target as
   colibri, and with no other key. Zig keys a dependency by its build root and its options,
   so the two requests give one object. A difference fails the link with a duplicate symbol.
   docs/usage.md, "Naming chapulin beside colibri", lists the options.
3. colibri's object file for TLS over TCP carries `JWS=on` and `SCRAM=on` on a host target,
   as it carries `DNSSEC=on` (decision 142). chapulin refuses each of the three in a device
   object, so they are `off` there. No build option of colibri turns them on or off.
4. colibri passes chapulin the target its dependent gave it, unchanged. A release that changes
   the pin, an option or a key of the request says so in its notes, and colibri tells its
   consumers before the release.

The alternatives refused:
- A public name for chapulin's module, which the owner first chose. A program would then
  reach chapulin through colibri.
- A colibri wrapper for each chapulin feature that a consumer wants, as decision 142 did for
  DNSSEC. colibri would grow a module for crypto that HTTP does not use.
- JWS and SCRAM behind a build option of colibri, off by default. Two packages of one program
  that pass different options get two copies of chapulin, and the link fails.

This amends decision 142's reason "a program reaches chapulin only through the objects colibri
builds": a program now reaches it by its own request, equal to colibri's.

Cost: every program that links colibri on a host target holds the JWS and SCRAM code. A
program that names chapulin copies colibri's request, and changes it when colibri does.
