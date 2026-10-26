// The Node router of colibri's router benchmark: find-my-way, under Fastify. It registers the
// routes of ../github_routes.txt, then matches every route's path, the given number of rounds,
// and prints the nanoseconds of one match. A JIT runs it, so callgrind does not count it.
//
//   node main.js <routes file> <rounds>
import { readFileSync } from 'node:fs';
import FindMyWay from 'find-my-way';

const rounds = Number(process.argv[3]);
const routes = readFileSync(process.argv[2], 'utf8').trim().split('\n').map((line) => line.split(' '));
const router = FindMyWay();
const nothing = () => {};
for (const [method, path] of routes) router.on(method, path, nothing);
for (const [method, path] of routes) {
  if (router.find(method, path) === null) throw new Error(`no route for ${method} ${path}`);
}
// Rounds the JIT compiles the loop in, which the time leaves out.
const warmup_rounds = 2000;
for (let round = 0; round < warmup_rounds; round++) {
  for (const [method, path] of routes) router.find(method, path);
}
let found = 0;
const start = process.hrtime.bigint();
for (let round = 0; round < rounds; round++) {
  for (const [method, path] of routes) {
    if (router.find(method, path) !== null) found++;
  }
}
const elapsed = Number(process.hrtime.bigint() - start);
const matches = rounds * routes.length;
console.log(`find-my-way matches=${matches} found=${found} ns_per_match=${(elapsed / matches).toFixed(1)}`);
