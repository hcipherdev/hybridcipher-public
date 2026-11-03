# HybridCipher Desktop user guide

Static help pages for the website, illustrated with screenshots of the real desktop UI.

- `site/` — the pages to publish (`personal.html`, `team.html`), their shared `guide.css` and
  `guide.js`, and the screenshots under `site/img/`.
- `capture/` — scripts that regenerate the screenshots.

## How the screenshots are made

`capture/capture-personal.js` and `capture/capture-team.js` open `../src/index.html` in
headless Chromium with `capture/mock-tauri.js` standing in for the Tauri backend
(`capture/mock-team.js` adds the team data). The mocks return made-up demo data (personal
user `alex@example.com`; team "Northwind Studio" with admin `maria@northwind.example`; fake
recovery keys and invitation codes), so no real account, key or file appears in the guide.
Each script clicks through the same buttons a user would and saves one JPEG per step, with a
highlight ring on the control the step describes.

## Regenerate after a UI change

```bash
cd apps/desktop/user-guide/capture
node capture-personal.js
node capture-team.js
```

Uses the Playwright package available in the environment (`require('playwright')`). If a
button id or label changes in `src/`, update the matching selector in the capture script.
