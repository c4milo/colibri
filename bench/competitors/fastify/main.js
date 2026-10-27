// Node's Fastify, a server of colibri's request benchmark (design §8 step 13f), as bench/run.sh
// --latency starts it: one thread, the routes of --routes registered with Fastify's router,
// find-my-way, and every route answered with 200 and "ok\n". A Fastify server speaks h11, or h2
// alone, so --h2 starts one that speaks h2 in cleartext with prior knowledge. With --tls too it
// speaks h2 over TLS, over the identity whose <prefix>.chain.pem and <prefix>.key.pem --tls names.
//
//   node main.js --port <port> --routes <routes file> [--h2 [--tls <prefix>]]
import { readFileSync } from 'node:fs';
import Fastify from 'fastify';

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
};
const port = Number(option('--port'));
const routesFile = option('--routes');
if (!Number.isInteger(port) || routesFile === undefined) {
  console.error('usage: node main.js --port <port> --routes <routes file> [--h2 [--tls <prefix>]]');
  process.exit(2);
}
const prefix = option('--tls');
const https = prefix === undefined ? undefined : {
  cert: readFileSync(`${prefix}.chain.pem`),
  key: readFileSync(`${prefix}.key.pem`),
  minVersion: 'TLSv1.3',
};
const server = Fastify({ http2: args.includes('--h2'), https, logger: false });
const ok = (_request, reply) => {
  reply.header('content-type', 'text/plain; charset=utf-8').send('ok\n');
};
for (const line of readFileSync(routesFile, 'utf8').trim().split('\n')) {
  const [method, path] = line.split(' ');
  server.route({ method, url: path, handler: ok });
}
const address = await server.listen({ host: '127.0.0.1', port });
console.log(`listening on port ${new URL(address).port}`);
