# TLN Hackathon 2026 — NETRA (Speedrun)

## Mission

Build **NETRA**, a client-side phishing-protection toolkit, for the
[TLN Cybersecurity Challenge 2026](https://tln-cybersecurity-challenge.devpost.com/).

- **Hard deadline: 2026-09-20 10:00 EDT = 14:00 UTC = 22:00 +08 (local)**
- Judging: technical implementation, creativity, cybersecurity relevance,
  practicality/impact, demo quality, execution.
- Judges skew senior (Amazon engineers, AppSec analyst) → prefer real technique
  over LLM wrappers. No paid API keys available → 100% local heuristics.

## Submission checklist (Devpost)

- [x] Working prototype + link judges can test (live web demo + load-unpacked ext)
- [x] Project name, description, technologies used (README.md = paste-ready)
- [x] Demo link: https://georgefifth.github.io/netra/ + https://github.com/Georgefifth/netra
- [ ] Video <5min (skipped — user opted for live demo)
- [x] AI disclosure: built with Devin (AI pair programmer) — disclosed
- [x] Cover + slides: Figma file https://www.figma.com/design/5uARhJgnKzq2BnITnskraX
      exported to assets/*.png (cover 1600×900, slides 1920×1080)
- [ ] Devpost form submission — user does it (their account)

## Figma MCP

Official remote server configured via `devin mcp add figma https://mcp.figma.com/mcp`
(OAuth done, tokens persisted). Write via `use_figma` (Plugin API JS, top-level
await + return, colors 0–1, load fonts before text, no `V`/`H` path shorthand,
return node IDs). planKey: `team::1681314748823569201`. `figma-bridge/` is a
local polling fallback if MCP ever breaks.

## Architecture

```
TLN/
├── engine.js          # Pure JS analysis engine (shared, no deps)
├── extension/         # Manifest V3 WebExtension (Chrome + Firefox)
│   ├── manifest.json
│   ├── background.js  # badge/icon, tab risk state
│   ├── content.js     # DOM scan: forms, links, urgency text → inject warning
│   ├── warning.js/css # in-page warning banner
│   ├── popup.html/js  # scan current tab + paste-URL analyzer
│   └── icons/
├── web/               # GitHub Pages site (live demo for judges)
│   ├── index.html     # landing + paste-URL analyzer (reuses ../engine.js)
│   └── demo/          # fake phishing sites to demo detection (paypa1 clone etc.)
└── README.md          # Devpost-facing doc: problem, solution, tech, usage
```

## Engine capabilities (all local, zero network)

- Typosquatting: Levenshtein distance vs top-brand list (paypal, google, ...)
- Homoglyph/confusable detection (l↔1, o↔0, rn↔m, Cyrillic lookalikes)
- Punycode/IDN (`xn--`), IP-as-host, `@` in URL, URL shorteners, sus TLDs
- Excessive subdomains, hyphens, domain-length/entropy heuristics
- Page signals (content script): password forms posting off-domain / over HTTP,
  hidden iframes, urgency/scare keyword density, external link ratio
- Output: 0-100 risk score + per-signal explanations (education angle)

## Demo strategy

- Web demo page = the "live link" judges can test instantly.
- `web/demo/` hosts fake phishing pages → extension + analyzer both flag them.
- Extension load-unpacked tested in Firefox (about:debugging); MV3 also
  Chrome-compatible for judges.
- Optional: /etc/hosts trick `paypa1-secure.example → 127.0.0.1` for video.

## Constraints / rules

- Student-only hack; original work during hack window; AI use disclosed.
- NO malware/credential stealers — defensive tooling only. Fake login pages in
  `web/demo/` must clearly be demos (no real credential exfiltration; form
  submit intercepted locally).
- Keep it fast: single-purpose files, no build step, no frameworks (vanilla JS
  + CSS). Zero npm deps → judges run it instantly.

## Timeline (local +08)

| Time  | Task |
|-------|------|
| ~19:00 | AGENTS.md + scaffold (done) |
| 19:10–20:30 | engine.js + extension + web demo |
| 20:30–21:00 | test in Firefox, deploy GitHub repo + Pages |
| 21:00–21:40 | README + Devpost writeup text |
| 21:40–22:00 | buffer / optional ffmpeg screen-record video |

## Deploy

```bash
gh repo create netra --public --source . --push
gh api repos/Georgefifth/netra/pages -f build_type=workflow  # or branch pages
# Pages source: main /web (or gh-pages branch)
```

Git identity: yap <yapisaac0@gmail.com>; gh user: Georgefifth.
