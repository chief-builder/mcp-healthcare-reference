---
name: docs-sync
description: "Bring the stakeholder HTML pages (docs/showcase/, docs/walkthrough/) back in sync with the code, driven by git diff against each page's recorded commit. User-invoked only — suggest it after a phase gate flips green or a remediation batch lands, but never run it unasked."
---

# docs-sync — keep the stakeholder HTML honest

The repo ships seven single-file HTML pages for readers who never open the
code: `docs/showcase/{product,technical-overview,token-lifecycle}.html` and
`docs/walkthrough/{overall,modules}-{functional,technical}.html`. They go
stale silently — this skill makes staleness detectable and updates mechanical.

## Contract (every page)

- **Manifest** in `<head>`:
  `<script type="application/json" id="canvas-manifest">` holding
  `generated` (YYYY-MM-DD), `commit` (full `git rev-parse HEAD`), `phase`,
  and `sections` (id → data-sources).
- **Sections** carry provenance:
  `<section id="kebab-id" data-sources="plugins/dpop-check/, deck/">` —
  repo paths the content derives from; directory prefixes end with `/`.
- **Footer stamp**, visible: `Documents the lab as of Phase N · YYYY-MM-DD`.
- **Self-contained**: inline CSS/JS/SVG only; no CDN, fonts, remote images,
  or fetch. Plain `<a href>` links out are fine.

## Modes

| State | Mode |
|-------|------|
| Page has no manifest | **Retrofit** (one-time) |
| Manifest present | **Update** (default) |
| User passes `rebuild <page>` | Rebuild that page from scratch |

## Retrofit (first run per page)

Read the page, map each section to the repo paths it actually describes, add
manifest + `data-sources` + footer stamp. While mapping, verify the content
against HEAD — a claim you can't point at a current file gets fixed now, not
stamped as fresh. Audiences are already encoded in the page split
(product / technical / functional); don't re-ask.

## Update

1. Per page, read the manifest `commit`; run
   `git diff --name-only <commit>..HEAD`. For the why, read
   `git log <commit>..HEAD --format='%h %s'` and the CLAUDE.md status block.
2. Map changed paths to sections via `data-sources` prefixes; rewrite those
   sections. Changed paths claimed by **no** section on **any** page mean an
   undocumented capability — tell the user which paths, and either add a
   section or get an explicit "not stakeholder-relevant".
3. Re-derive every number this run (probe counts from `tests/phaseN.sh`
   output or the test files, container/RAM figures from compose) — never
   copy one from the old page. Never carry a claim you can't still point at.
4. Refresh manifest, footer stamp, and any current-state/phase-status
   content on every touched page.
5. Manifest commit unknown to git, or most sections stale → say so and
   rebuild instead.

## Sources of truth

North star and phases: `docs/prototype-plan.md`. Architecture:
`docs/mcp-e2e-reference-architecture.md`. Token shape:
`docs/mcp-token-claims-contract.md` §3. Broker:
`docs/vendor-token-broker-design.md`. Known gaps: open GitHub issues
(`gh issue list`) + tracked gaps in CLAUDE.md — report them candidly.

## Self-check (before reporting done)

Every internal `#link` resolves · no external `script`/`link`/`img` loads ·
every `data-sources` path exists at HEAD · manifest parses · footer stamp
matches manifest · no near-empty sections · **no secrets**: nothing from any
`.env`, no Auth0 tenant domain, no client secrets or GitHub client IDs —
these pages get shared outside the lab. Fix and re-check until all pass.
Suggest committing as `docs(sync): <pages> as of Phase N`.
