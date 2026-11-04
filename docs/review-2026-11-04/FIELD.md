# The Field: display and UI review, 4 November 2026

The live 2026-11-04 edition (400,091 records, `cves.22d4ca02….bin.gz`) was
loaded into a local copy of the page and captured in headless Chromium
(SwiftShader WebGL) at 1440×900, 1024×768 and 390×844, in every
arrangement and colouring, with a pinned record, the records table, a
selection and a publication cut. The before/after pairs in this folder are
from that run.

## Defects

| What a reader saw | Cause | Now |
| --- | --- | --- |
| Group labels cut their own numbers: "115,551 · KEV 3…", "78,230 · KEV 1,…", "Awaiting Analys…", "CWE-89 SQL inje…" | `.f-label.group` had `max-width: 115px; overflow: hidden; text-overflow: ellipsis` on the whole label | The name wraps to two lines at 19ch; the count line never truncates (`field-d-status.jpg`, `field-d-cna.jpg`) |
| The CVSS × EPSS grid said "They measure different things, and no diagonal is expected" | Contradicted by the CVE Ecosystem page's own data: the share of CVEs with EPSS ≥ 10% rises about twentyfold from Low to Critical | The text says what each axis measures and claims no relationship either way |
| "400,091 placed through this month · 400,091 match the filters across all months. Top-group limits may exclude matches." with no time cut set | One template for every state | "All 400,091 records matching the filters are placed." or "361,855 of 400,091 … are placed; this arrangement shows the 48 largest assigners."; the cut adds "… published by the end of 2019-06" |
| "page 1 of 10003" | page count not formatted | "page 1 of 10,003" |
| "other" shown as a vendor name in the table, details, selection and JSON export | vendor index 0 is the export's placeholder for "no vendor named" | "—" in the table, "no vendor named" in details and selection, `null` in the export |
| Editing the address (or back/forward between hashes) did nothing until a reload | no `hashchange` listener | the view is re-read from the hash; `writeHash` uses `replaceState`, so there is no loop |
| A pinned record (camera flown to it) was hard to find among thousands of same-colour points | the only marker was a white point drawn at size 9 | a ring in screen space follows the pinned record (`field-d-inspect.jpg`) |
| Orbiting to look around a pinned record closed its details | `pointerdown` anywhere on the canvas called `closeInspector()` | only a click on empty canvas releases it |
| "EPSS 100.00%" for 52 records | EPSS is stored as round(p × 10000), so 10000 means ≥ 99.995% | "≈100%" |

## Improvements

- Record details are a labelled list (Published, CVSS, EPSS, Assigner,
  Vendor, Weakness, NVD, Public PoC, KEV) instead of three dot-separated
  runs with the assigner and vendor unlabelled. The hover tip uses the
  same list.
- The pinned record links to its own change history in the Mutation
  Observatory (`observatory.html#cve=…`, which already links back) instead
  of the generic CVSS Score Changes and EPSS Volatility pages.
- Camera distance is fitted to each arrangement's extent and the canvas
  shape, so the timeline no longer sits in the middle third of the canvas
  and a portrait phone gets a nearer view. Group arrangements look down more
  steeply, so more labels clear the collision check (labelled groups at
  1440×900, counted in the DOM: assigners 21 → 28 of 48, vendors 21 → 32
  of 48, weaknesses 15 → 16 of 30). The grid's row headings
  are right-aligned and no longer collide with the first column's counts;
  "Medium" and "1–10%" were hidden before (`field-d-grid.jpg`).
- "Reset view" moved from the bottom of the rail to the toolbar. On a
  phone the toolbar fits on one row and the page lede yields to the
  arrangement's own explanation, so the canvas is about 90 px taller
  (`field-m-time.jpg`).
- Percentages match the rest of the site ("0.44%", not "0.44 %"). The
  edition stamp reads "Edition 2026-11-04 09:49 UTC. Playback keeps this
  edition's scores, EPSS and KEV status." instead of a raw ISO timestamp.

## Follow-up (same day)

- Browse records sorts by any column (click a heading; again to reverse).
  Missing values sort last either way; each order is computed once per
  column and cached, so playback with the table open stays one pass over
  the records. On the live edition a sort takes 114–160 ms. The smoke test
  checks both directions and `aria-sort`.
- `field.css`: the body grid takes the last row, so the Alias Graph draft,
  which shares the stylesheet but has no toolbar, lays out correctly.

## Copy

All Field text lives in `site/js/field.js` and `site/field.html`, outside
`editorial.js`, so it was reviewed here.

- Arrangement names say what they show: "The clock · publication → PoC →
  KEV" → "Days to PoC and KEV"; "Severity × predicted exploitation" →
  "CVSS × EPSS grid"; "By NVD queue status" → "By NVD status" (Analyzed
  and Modified are not queue statuses).
- "the current selection" (which also names the box selection) → "the
  matching records". CNA is spelled out once. Methods state the point
  height for every group arrangement and that EPSS bands come from the
  unrounded probability.
- Help text rewritten plainly: "describe exactly what you caught —
  assigners, weaknesses, vendors, scores, exploitation" → "describe the
  selection"; one help paragraph split into Navigate and what the address
  keeps. The selection note "Counts are exact over the N selected records
  in this view" is cut (the panel heading already gives N).
- The header lede now lists NVD status; the `<title>` and meta description
  lost the trailing period and "by CVSS and EPSS bucket".
- American spelling (Color, normalized), as on every other page.

## Code

`site/css/field.css` ended in a "Review fixes" block that redefined about
twenty rules from above it, including two conflicting narrow-screen
blocks. It is now one stylesheet with one narrow-screen block and one phone
block; the rendered layout was compared before and after.

## Checks

- `python tools/field_smoke.py` (fixture) and
  `python tools/field_smoke.py --site <assembled copy with the live
  edition>` both pass. New assertions: the pinned-record ring is visible,
  and an edited hash re-focuses another record. Updated expectations: the
  percent format and the edition date.
- No console errors other than blocked web fonts in the offline harness.

## Left as is

- Group arrangements still hide labels that would collide; zooming in
  reveals them (the collision check runs every frame). Showing all 48 at
  the default distance would need smaller type than the page uses.
- The timeline is a long, flat ribbon (x spans 460 units, score 36, EPSS
  56); that is the design, not a framing problem.
