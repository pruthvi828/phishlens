// NETRA Bridge — long-polls localhost:3055 for Plugin API code, runs it,
// posts the result back. Whatever Devin sends lands on the canvas live.
const BASE = "http://localhost:3055";

figma.showUI(__html__, { width: 260, height: 120, title: "NETRA Bridge" });
figma.ui.postMessage({ type: "status", text: "polling localhost:3055…" });

function jsonable(v) {
  try { return JSON.parse(JSON.stringify(v)); }
  catch (e) { return String(v); }
}

async function loop() {
  try {
    const r = await fetch(BASE + "/poll");
    if (r.status === 200) {
      const job = await r.json();
      let out;
      try {
        const fn = new Function("figma", `"use strict"; return (async () => { ${job.code} })()`);
        out = { ok: true, result: jsonable(await fn(figma)) };
      } catch (e) {
        out = { ok: false, error: String((e && e.message) || e) };
      }
      try {
        await fetch(BASE + "/result", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: job.id, ...out }),
        });
      } catch (e) {}
      figma.ui.postMessage({ type: "status", text: out.ok ? "last job: ok" : "last job: " + out.error });
    }
  } catch (e) {
    figma.ui.postMessage({ type: "status", text: "bridge offline — start server.js" });
    await new Promise((r) => setTimeout(r, 2000));
  }
  setTimeout(loop, 250);
}
loop();
