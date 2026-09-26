const list = await (await fetch('http://127.0.0.1:9229/json')).json();
const target = list[0];
const ws = new WebSocket(target.webSocketDebuggerUrl, { headers: { Origin: 'http://localhost' } });
let id = 0; const pend = new Map();
const call = (method, params = {}) => new Promise(r => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); } };
await new Promise(r => ws.onopen = r);
const out = process.argv[2];
const fs = await import('node:fs');
let maxUsed = 0, maxTotal = 0, maxEmb = 0;
const stop = Date.now() + Number(process.argv[3] || 240000);
while (Date.now() < stop) {
  const t = Date.now();
  const h = await call('Runtime.getHeapUsage');
  const r = h.result || {};
  maxUsed = Math.max(maxUsed, r.usedSize || 0); maxTotal = Math.max(maxTotal, r.totalSize || 0); maxEmb = Math.max(maxEmb, r.embedderHeapUsedSize || 0);
  fs.appendFileSync(out, JSON.stringify({ t, ...r }) + '\n');
  if (fs.existsSync(out + '.done')) break;
  await new Promise(r => setTimeout(r, 250));
}
const to = p => Promise.race([p, new Promise(r => setTimeout(() => r({}), 5000))]);
await to(call('HeapProfiler.collectGarbage'));
const after = (await to(call('Runtime.getHeapUsage'))).result;
console.log(JSON.stringify({ target: target.title, maxUsed, maxTotal, maxEmb, afterGC: after, samples: fs.readFileSync(out,'utf8').split('\n').length - 1 }));
ws.close(); process.exit(0);
