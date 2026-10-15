// NETRA Cover Generator — draws a 1600x900 Devpost cover as editable nodes.
// Run: Figma → Plugins → Development → Import plugin from manifest → run it.

const C = {
  bg:      { r: 0.059, g: 0.090, b: 0.165 }, // #0f172a
  card:    { r: 0.118, g: 0.161, b: 0.231 }, // #1e293b
  border:  { r: 0.200, g: 0.255, b: 0.333 }, // #334155
  teal:    { r: 0.176, g: 0.831, b: 0.749 }, // #2dd4bf
  blue:    { r: 0.220, g: 0.741, b: 0.973 }, // #38bdf8
  white:   { r: 0.886, g: 0.910, b: 0.941 }, // #e2e8f0
  muted:   { r: 0.580, g: 0.639, b: 0.721 }, // #94a3b8
  red:     { r: 0.863, g: 0.149, b: 0.149 }, // #dc2626
};

function rect(w, h, color, radius = 0) {
  const r = figma.createRectangle();
  r.resize(w, h);
  r.fills = [{ type: "SOLID", color }];
  if (radius) r.cornerRadius = radius;
  return r;
}

async function text(str, size, color, style = "Bold") {
  const t = figma.createText();
  await figma.loadFontAsync({ family: "Inter", style });
  t.fontName = { family: "Inter", style };
  t.characters = str;
  t.fontSize = size;
  t.fills = [{ type: "SOLID", color }];
  return t;
}

async function main() {
  const frame = figma.createFrame();
  frame.name = "NETRA Cover 1600×900";
  frame.resize(1600, 900);
  frame.fills = [{ type: "SOLID", color: C.bg }];
  frame.clipsContent = true;

  // subtle glow circles in background
  const glow1 = figma.createEllipse();
  glow1.resize(900, 900); glow1.x = -250; glow1.y = -300;
  glow1.fills = [{ type: "SOLID", color: C.teal, opacity: 0.06 }];
  frame.appendChild(glow1);
  const glow2 = figma.createEllipse();
  glow2.resize(700, 700); glow2.x = 1150; glow2.y = 450;
  glow2.fills = [{ type: "SOLID", color: C.blue, opacity: 0.06 }];
  frame.appendChild(glow2);

  // ---- shield + magnifier logo (left-center) ----
  const logo = figma.createFrame();
  logo.name = "logo";
  logo.resize(320, 320);
  logo.fills = [];
  logo.x = 150; logo.y = 230;
  frame.appendChild(logo);

  const shield = figma.createVector();
  shield.vectorPaths = [{
    windingRule: "NONZERO",
    data: "M160 10 L300 55 V165 C300 235 240 285 160 315 C80 285 20 235 20 165 V55 Z",
  }];
  shield.fills = [{ type: "SOLID", color: C.teal }];
  logo.appendChild(shield);

  // magnifier: ring + handle + "!"
  const lens = figma.createEllipse();
  lens.resize(110, 110);
  lens.x = 105; lens.y = 80;
  lens.fills = [{ type: "SOLID", color: C.bg, opacity: 0.25 }];
  lens.strokes = [{ type: "SOLID", color: { r: 1, g: 1, b: 1 } }];
  lens.strokeWeight = 14;
  logo.appendChild(lens);

  const handle = figma.createVector();
  handle.vectorPaths = [{
    windingRule: "NONZERO",
    data: "M0 0 L58 58 L42 74 L-16 16 Z",
  }];
  handle.fills = [{ type: "SOLID", color: { r: 1, g: 1, b: 1 } }];
  handle.x = 195; handle.y = 172;
  logo.appendChild(handle);

  const bang = await text("!", 64, { r: 1, g: 1, b: 1 });
  bang.x = 148; bang.y = 102;
  logo.appendChild(bang);

  // ---- title / tagline (right side) ----
  const title = await text("NETRA", 120, C.white);
  title.x = 540; title.y = 250;
  title.fills = [{
    type: "GRADIENT_LINEAR",
    gradientTransform: [[1, 0, 0], [0, 1, 0]],
    gradientStops: [
      { position: 0, color: { ...C.teal, a: 1 } },
      { position: 1, color: { ...C.blue, a: 1 } },
    ],
  }];
  frame.appendChild(title);

  const tag = await text(
    "Real-time, private, explainable phishing protection", 40, C.muted, "Medium");
  tag.x = 545; tag.y = 395;
  frame.appendChild(tag);

  const sub = await text(
    "100% client-side · browser extension + web analyzer", 28, C.muted, "Regular");
  sub.x = 545; sub.y = 455;
  frame.appendChild(sub);

  // ---- four detection chips (2×2 grid) ----
  const layers = [
    ["Typosquat & homoglyph radar", "paypa1 · g00gle · xn-- punycode"],
    ["URL forensics", "user@host · raw IP · abused TLDs · entropy"],
    ["Page-content signals", "credential forms · CVV/SSN · urgency copy"],
    ["Explainable 0-100 score", "every flag shows its reason"],
  ];
  for (let i = 0; i < layers.length; i++) {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 545 + col * 455, y = 545 + row * 116;
    const card = rect(430, 96, C.card, 14);
    card.x = x; card.y = y;
    card.strokes = [{ type: "SOLID", color: C.border }];
    card.strokeWeight = 1.5;
    frame.appendChild(card);
    const t1 = await text(layers[i][0], 26, C.teal, "Bold");
    t1.x = x + 22; t1.y = y + 15;
    frame.appendChild(t1);
    const t2 = await text(layers[i][1], 20, C.muted, "Regular");
    t2.x = x + 22; t2.y = y + 55;
    frame.appendChild(t2);
  }

  // ---- bottom badge ----
  const badge = rect(560, 52, C.card, 26);
  badge.x = 545; badge.y = 800;
  badge.strokes = [{ type: "SOLID", color: C.teal }];
  badge.strokeWeight = 1.5;
  frame.appendChild(badge);
  const bt = await text("TLN CYBERSECURITY CHALLENGE 2026", 22, C.teal, "Bold");
  bt.x = 575; bt.y = 814;
  frame.appendChild(bt);

  figma.currentPage.appendChild(frame);
  figma.viewport.scrollAndZoomIntoView([frame]);
  figma.closePlugin("NETRA cover created — select the frame and export PNG (2x).");
}

main().catch((e) => figma.closePlugin("Error: " + e.message));
