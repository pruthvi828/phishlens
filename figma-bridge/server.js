#!/usr/bin/env node
// NETRA ↔ Figma bridge server (stdlib only).
// The Figma plugin long-polls GET /poll for {id, code}, executes it against the
// Plugin API, then POSTs /result {id, ok, result|error}.
// Usage:
//   node server.js                 → run bridge on :3055
//   node server.js send 'CODE'     → enqueue code, print result, exit
//   curl -XPOST localhost:3055/cmd -d '{"code":"..."}'
const http = require("http");
const PORT = 3055;
const pending = [];   // [{id, code}]
const waiters = [];   // long-poll responses waiting for work
const results = new Map(); // id -> {res( http res )}
let nextId = 1;

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  if (req.method === "GET" && req.url === "/poll") {
    if (pending.length) {
      const job = pending.shift();
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify(job));
    }
    waiters.push(res);
    req.setTimeout(30000, () => {
      const i = waiters.indexOf(res);
      if (i >= 0) { waiters.splice(i, 1); res.writeHead(204); res.end(); }
    });
    return;
  }

  if (req.method === "POST" && (req.url === "/result" || req.url === "/cmd")) {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let data = {};
      try { data = JSON.parse(body || "{}"); } catch (e) {}
      if (req.url === "/result") {
        const r = results.get(data.id);
        results.delete(data.id);
        res.writeHead(200); res.end("ok");
        if (r) r(data);
        return;
      }
      // /cmd — enqueue and hold this response until the plugin reports back
      const id = nextId++;
      const job = { id, code: data.code || "" };
      results.set(id, (out) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(out));
      });
      req.setTimeout(60000, () => {
        if (results.delete(id)) {
          res.writeHead(504); res.end('{"ok":false,"error":"timeout waiting for plugin"}');
        }
      });
      if (waiters.length) {
        const w = waiters.shift();
        w.writeHead(200, { "Content-Type": "application/json" });
        w.end(JSON.stringify(job));
      } else pending.push(job);
    });
    return;
  }

  res.writeHead(404); res.end();
});

if (process.argv[2] === "send") {
  const code = process.argv[3];
  const rq = http.request(
    { host: "localhost", port: PORT, path: "/cmd", method: "POST",
      headers: { "Content-Type": "application/json" } },
    (r) => r.pipe(process.stdout));
  rq.on("error", (e) => { console.error("bridge server not running:", e.message); process.exit(1); });
  rq.end(JSON.stringify({ code }));
} else {
  server.listen(PORT, () => console.log(`figma bridge on http://localhost:${PORT}`));
}
