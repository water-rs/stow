const ws = new WebSocket('ws://127.0.0.1:9229/ws', { headers: { Origin: 'http://localhost' } });
ws.onerror = e => { console.log('error', e.message || e.type); process.exit(1); };
ws.onclose = e => { console.log('close', e.code, e.reason); };
ws.onopen = () => { console.log('open'); ws.send(JSON.stringify({id:1,method:'Runtime.getHeapUsage'})); };
ws.onmessage = e => { console.log('msg', e.data.slice(0,300)); process.exit(0); };
setTimeout(()=>{console.log('timeout', ws.readyState);process.exit(2)},8000);
