// The Traffic cost CPU pass's reference workload (stow#932): a fixed
// program `stow-admin traffic-cost cpu` evaluates in the edge isolate
// through the inspector, before and after every lane, so each lane's CPU
// is gated relative to what this costs on the same runner. It does the
// two kinds of work the lanes spend their CPU on, and changing anything
// here changes every budget's unit: re-derive WORKER_CPU_BUDGETS and the
// checksum in `cpu.rs` with it.
(() => {
  // The scheduler's scans over its in-memory graph, at the graph's
  // layout (68-byte nodes, 48-byte states) and the Traffic cost
  // fixture's 100k nodes: a status tally keyed by label and the oldest
  // pending node's state, as `Graph::admin_status` walks them.
  const n = 100000;
  const nodeWords = 17;
  const stateWords = 12;
  const nodes = new Int32Array(n * nodeWords);
  const states = new Int32Array(n * stateWords);
  let seed = 0x2545f491;
  for (let i = 0; i < nodes.length; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) | 0;
    nodes[i] = seed;
  }
  for (let i = 0; i < states.length; i++) {
    seed = (Math.imul(seed, 22695477) + 1) | 0;
    states[i] = seed;
  }
  const labels = ["pending", "blocked", "dispatched", "running", "completed", "failed", "published", "free"];
  let hash = 0;
  for (let pass = 0; pass < 6; pass++) {
    const counts = new Map();
    let oldest = 0x7fffffff;
    for (let i = 0; i < n; i++) {
      const label = labels[nodes[i * nodeWords + pass] & 7];
      if (label === "published" || label === "free") continue;
      counts.set(label, (counts.get(label) ?? 0) + 1);
      if (label === "pending") {
        const first = states[i * stateWords + 3];
        if (first < oldest) oldest = first;
      }
    }
    for (const [label, count] of counts) hash = (Math.imul(hash, 31) + label.length * count) | 0;
    hash = (hash ^ oldest) | 0;
  }

  // Request-sized JSON: an operator listing's rows serialized, parsed
  // back and hashed byte by byte.
  const rows = [];
  for (let i = 0; i < 2000; i++) {
    rows.push({
      task_id: `t-${i.toString(36)}`,
      crate_name: `crate${i % 97}`,
      version: `1.${i % 13}.${i % 7}`,
      target: "x86_64-unknown-linux-gnu",
      attempt: i % 5,
      claimed_at: `2026-10-25T07:${String(i % 60).padStart(2, "0")}:00Z`,
    });
  }
  for (let round = 0; round < 6; round++) {
    const text = JSON.stringify(rows);
    const parsed = JSON.parse(text);
    for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 16777619);
    hash = (hash + parsed.length) | 0;
  }
  return hash >>> 0;
})()
