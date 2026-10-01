---
name: docs-sync
description: "Bring the stakeholder HTML pages (docs/showcase/, docs/walkthrough/) back in sync with the code, driven by git diff against each page's recorded commit. User-invoked only — suggest it after a phase gate flips green or a remediation batch lands, but never run it unasked."
---

# docs-sync — keep the stakeholder HTML honest

The repo ships seven HTML pages for readers who never open the
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
- **Self-contained**: inline CSS/JS/SVG, plus local images under
  `docs/walkthrough/assets/`; no CDN, fonts, remote images, or fetch. Plain
  `<a href>` links out are fine.

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
4. New-feature enumeration sweep. When the diff ADDS a capability (a
   plugin, claim, probe family, datastore, client), prefix matching will
   miss the pages that should mention it but don't: enumerations that list
   its siblings (plugin lists, control ledgers, evidence sources, probe
   coverage, "implemented" buckets, glossaries, diagram node labels) won't
   be flagged because their own sources didn't change. Grep every page for
   the siblings' names and update each list that now omits the newcomer.
   Prose lists rot faster than fact tables — a 2026-07-14 editorial pass
   found ~15 such omissions (all DPoP/OpenBao-era), zero false claims.
5. Refresh manifest, footer stamp, and any current-state/phase-status
   content on every touched page.
6. Manifest commit unknown to git, or most sections stale → say so and
   rebuild instead.

## Sources of truth

North star and phases: `docs/prototype-plan.md`. Architecture:
`docs/mcp-e2e-reference-architecture.md`. Token shape:
`docs/mcp-token-claims-contract.md` §3. Broker:
`docs/vendor-token-broker-design.md`. Known gaps: open GitHub issues
(`gh issue list`) + tracked gaps in CLAUDE.md — report them candidly.

## Publish (automated)

The pages are served publicly by GitHub Pages from the separate public repo
`chief-builder/mcp-healthcare-reference-docs` (the site predates this repo
becoming public, and keeps the published set separate). `.github/workflows/mirror-docs.yml` mirrors the published
set — `docs/index.html`, `docs/.nojekyll`, `docs/showcase/`,
`docs/walkthrough/`, and the docs repo's README from
`.github/docs-mirror/README.md` — automatically on every push to main
touching those paths (or on demand via `workflow_dispatch`). After a sync lands, confirm the workflow ran (`gh run list
--workflow=mirror-docs`) and spot-check the live URL:
https://chief-builder.github.io/mcp-healthcare-reference-docs/.
The design .md docs are read in this repo, not on the site — never widen
what the workflow mirrors without deciding to.
Remember the site is PUBLIC: the no-secrets self-check below is what
stands between a sync and public exposure.

## Self-check (before reporting done)

Every internal `#link` resolves · no external `script`/`link`/`img` loads ·
every `data-sources` path exists at HEAD · manifest parses · footer stamp
matches manifest · no near-empty sections · **no secrets**: nothing from any
`.env`, no Auth0 tenant domain, no client secrets or GitHub client IDs —
these pages get shared outside the lab. Fix and re-check until all pass.
Suggest committing as `docs(sync): <pages> as of Phase N`.
