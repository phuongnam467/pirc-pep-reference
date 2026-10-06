// Miniature RESP2 server used ONLY by tests — runs as a separate child
// process so the store's synchronous worker bridge behaves exactly like it
// does against a real external Redis (main-thread blocking cannot deadlock
// a foreign process).
import net from 'node:net';

const withTtl = process.argv[2] === '1';
const state = new Map();
let counter = 0;

const server = net.createServer((sock) => {
  let acc = Buffer.alloc(0);
  sock.on('data', (chunk) => {
    acc = Buffer.concat([acc, chunk]);
    for (;;) {
      const parsed = readArray(acc);
      if (!parsed) return;
      acc = acc.subarray(parsed.consumed);
      const args = parsed.args.map(String);
      const cmd = args[0].toUpperCase();
      let reply;
      if (cmd === 'PING') reply = '+PONG\r\n';
      else if (cmd === 'SELECT' || cmd === 'AUTH') reply = '+OK\r\n';
      else if (cmd === 'SET') {
        const key = args[1];
        if (args.includes('NX') && state.has(key)) reply = '$-1\r\n';
        else {
          const pxIdx = args.indexOf('PX');
          if (pxIdx !== -1) state.set(`__ttl__${key}`, Number(args[pxIdx + 1]));
          state.set(key, '1');
          reply = '+OK\r\n';
        }
      } else if (cmd === 'EXISTS') reply = `:${state.has(args[1]) ? 1 : 0}\r\n`;
      else if (cmd === 'GET') reply = state.has(args[1]) ? '$1\r\n1\r\n' : '$-1\r\n';
      else if (cmd === 'INCRBY') {
        counter = (Number(state.get(args[1]) ?? 0)) + Number(args[2]);
        state.set(args[1], String(counter));
        reply = `:${counter}\r\n`;
      } else if (cmd === 'QUIT') { sock.end('+OK\r\n'); return; }
      else reply = `-ERR unknown command '${cmd}'\r\n`;
      sock.write(reply);
    }
  });
});

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  process.stdout.write(`READY ${port}\n`);
});

setTimeout(() => process.exit(0), 60_000); // safety: never leak a fixture

function readArray(buf) {
  if (buf.length === 0 || buf[0] !== 42 /* * */) return null;
  const nl = buf.indexOf('\r\n');
  if (nl === -1) return null;
  const n = Number(buf.toString('ascii', 1, nl));
  const args = [];
  let off = nl + 2;
  for (let i = 0; i < n; i++) {
    const hdrEnd = buf.indexOf('\r\n', off);
    if (hdrEnd === -1) return null;
    const len = Number(buf.toString('ascii', off + 1, hdrEnd));
    const bodyStart = hdrEnd + 2;
    if (buf.length < bodyStart + len + 2) return null;
    args.push(buf.toString('utf8', bodyStart, bodyStart + len));
    off = bodyStart + len + 2;
  }
  return { args, consumed: off };
}
