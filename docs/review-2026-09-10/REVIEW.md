# CyberMon review — 10 September 2026

CyberMon has a strong data pipeline and a distinctive visual identity. The Field is a promising instrument, but its displayed counts, time semantics, and cross-chart consistency need correction before its results can be treated as exact receipts. The most important work is accuracy and interaction reliability, followed by legibility and discovery.

## Scope and verification

- Reviewed checkout `53ba5ec`, with particular attention to `site/js/field.js`, its HTML/CSS, binary exporter/contracts/tests, shared rendering, editorial claims, and deployment workflows.
- Inspected the real [CyberMon site](https://devko.github.io/CyberMon/). All 22 standard pages returned HTTP 200, rendered edition metadata, and produced no JavaScript errors, failed HTTP responses, or error cards during the scan. The Field was inspected separately in all seven arrangements.
- Live edition: `2026-09-10T02:49:04Z`; Field: **371,161 records**, **1,703 KEV entries**, 2,475,852 compressed bytes. The deployed Field HTML, JS, and CSS match the reviewed checkout after normalizing line endings. Local committed data is an older edition; numerical comparisons below use live files from the same edition.
- Existing tests: **1,264 passed, 1 skipped**, one pytest deprecation warning, in 15.24 seconds.
- Browser: authorized headless Chromium through Playwright; desktop 1440×900, mobile viewport 390×844. Screenshots were captured and inspected in this run.
- Reproduced selection/time-cut, missing-CDN, point-size sharing, grouped-count and cross-chart discrepancies. Audited browser screenshots and DOM; this is not a full assistive-technology, physical-touch-device, or cross-browser certification. No GPU benchmark or live pipeline refresh was performed. Other modules received a broad smoke check and selected source review, not exhaustive interaction coverage.
- Initial resize scans flagged temporary mobile overflow before the shared 120 ms chart resize debounce ran. Fresh mobile navigation and a settled check measured 390 px document width. **Those transient measurements are not reported as persistent mobile bugs.**
- No application code changed. Existing untracked `site/alias.html` and `site/css/alias.css` were left untouched. Review artifacts are under this directory.

## Findings to fix

P1 = high priority correctness or availability problem. P2 = material usability, accessibility, or reliability problem. P3 = polish. These are the issues identified within the scope above, not a guarantee that no others exist.

### 1. P1 — Group counters include records the arrangement does not place

**Observed:** choose By assigner, vendor, or weakness. The header reports all matching records, while the layout only places the top 48/30 groups.

| Arrangement | Header says shown | Actually placed in groups | Header KEV | Actually placed KEV |
|---|---:|---:|---:|---:|
| Assigner | 371,161 | 337,013 | 1,703 | 1,445 |
| Vendor | 150,457 | 96,318 | 971 | 756 |
| Weakness | 371,161 | 318,342 | 1,703 | 1,292 |

The totals come from decoding the deployed binary and applying the exact group limits. `applyFilter()` counts before the top-group slice; `clusterLayout()` moves omitted groups to y=-999 without removing them from those counters. Consequently the displayed KEV share also describes a different population from the clusters.

**Fix:** maintain separate matched, placed, and time-visible masks/counts; label them explicitly, and optionally show an Other group. Use the placed/time-visible population for selection denominators.

Source: [field.js:300](D:/DEV/CyberMon/site/js/field.js:300), [field.js:425](D:/DEV/CyberMon/site/js/field.js:425), [field.js:629](D:/DEV/CyberMon/site/js/field.js:629). Evidence: steps 4–6 and `field-checks.json`.

### 2. P1 — Month changes leave a stale selection and stale totals

**Reproduction:** select the entire timeline, then move As of to January 1999. The canvas becomes empty but the selection panel and header still claim **371,161 selected / 1,703 KEV**. Clear the selection and the header correctly becomes zero.

`setAsOf()` recolours points without clearing or intersecting `selected`. The selection denominator also uses `shownCount`, ignoring the time cut. Group labels retain full-period counts as months play.

**Fix:** clear or recompute the selection on every time cut; derive receipts and labels from the same visible mask. If labels deliberately show final totals during playback, mark them as final totals.

Source: [field.js:616](D:/DEV/CyberMon/site/js/field.js:616), [field.js:900](D:/DEV/CyberMon/site/js/field.js:900). Evidence: step 9.

### 3. P1 — Lossy EPSS encoding changes analytical buckets

The exporter rounds probability ×10,000, then the browser classifies that rounded value. A raw probability of 0.00096 is below 0.1%, but becomes 10 and enters the next bucket. This also changes classifications around 1% and 10%.

**Observed:** 12 of the 16 scored Field cells disagree with the original CVE chart in the same live edition. Medium severity / EPSS <0.1% is **1,170 in the Field versus 1,545 in the chart**; High / EPSS 1–10% is **14,000 versus 13,915**.

**Fix:** export the source-computed bucket and threshold flags separately, or retain enough precision to preserve them. Add an integration assertion that the sixteen shared cells agree. Formatting precision must not decide analytical membership.

Source: [field_export.py:295](D:/DEV/CyberMon/pipeline/field_export.py:295), [field.js:452](D:/DEV/CyberMon/site/js/field.js:452), [metrics.py:786](D:/DEV/CyberMon/pipeline/metrics.py:786). Evidence: `extra-checks.json`.

### 4. P1 — Push deploy has a broken Field artifact command

The `gh run list` command contains literal backslash-n characters rather than a shell line continuation. Bash passes an extra `n` argument to `gh`. The step is `continue-on-error`, so a site deployment can proceed without the Field binary.

**Fix:** use a real newline/continuation, select a successful run that actually contains `field-latest`, and require the metadata plus matching binary before publishing a site that links to the instrument. A successful catch-up no-op can also lack that artifact, so selecting only the newest green workflow is insufficient.

Source: [ci.yml:164](D:/DEV/CyberMon/.github/workflows/ci.yml:164). Source-confirmed; no production workflow was triggered. Today's nightly has supplied a functioning Field, so this is not a claim that today's page is down.

### 5. P1 — Missing Three.js bypasses the error fallback

**Reproduction:** abort the `three.min.js` request. The page raises `THREE is not defined`, leaves the counters at em dashes, and never displays the intended library-failure notice.

`PAL` constructs `THREE.Color` instances at module initialization, before `boot()` checks whether `THREE` exists.

**Fix:** initialize Three-dependent objects after the availability check inside the guarded boot path. Exercise this failure mode in browser tests.

Source: [field.js:97](D:/DEV/CyberMon/site/js/field.js:97). Evidence: `field-checks.json`.

### 6. P1 — Historical wording describes data that is actually current

The timeline promises the score a CVE shipped with. It uses the latest score in today's record. As of only hides CVEs published after a month; EPSS, KEV membership, NVD status, rescores, and PoC flags remain today's values. A view labelled as of an old month can therefore show future knowledge.

**Fix:** say “published through [month], using [edition] attributes” and “current in-record score.” For a true historical replay, store dated attribute snapshots and apply each event only from its observed date. The existing export cannot reconstruct original scores across the corpus.

Source: [field.js:23](D:/DEV/CyberMon/site/js/field.js:23), [field.js:503](D:/DEV/CyberMon/site/js/field.js:503), [field_export.py:164](D:/DEV/CyberMon/pipeline/field_export.py:164).

### 7. P1 — “Score vs. reality” asserts an invalid diagonal expectation

The Field says scores tracking risk would make the mass follow a diagonal. CVSS base severity and EPSS probability measure different things; EPSS is itself a prediction, not observed exploitation. There is no general requirement that these axes align. Their bins also use different scales.

**Fix:** frame this as severity versus predicted exploitation, with observed KEV membership as a separate overlay. Explain the distinct dimensions rather than treating disagreement as proof of invalid severity scoring. FIRST explicitly distinguishes CVSS base scores from risk and describes EPSS as a next-30-day probability: [EPSS FAQ](https://www.first.org/epss/faq).

Source: [field.js:28](D:/DEV/CyberMon/site/js/field.js:28). Evidence: step 3.

### 8. P1 — The EPSS “grade” overstates what the cohort can establish

The EPSS module calls a sub-1% score before KEV inclusion the strongest form of miss. But KEV dateAdded is not the actual exploitation date; it does not establish an event inside the forecast's next 30 days. A probability below 1% is also not a claim that an event cannot happen. Selecting only eventual positives cannot establish calibration or overall forecast performance.

The page acknowledges seeding and model-version caveats, which is good, but those caveats do not fix the target/time-window mismatch.

**Fix:** retain the useful descriptive result as “EPSS before KEV listing.” To grade predictions, define an outcome window and cohort, include comparison/non-event records, and report coverage/effort and calibration with detection limitations. FIRST documents the horizon and evaluation framing in [how EPSS works](https://www.first.org/epss/how-it-works).

Source: [editorial.js:1633](D:/DEV/CyberMon/site/js/editorial.js:1633), [editorial.js:1666](D:/DEV/CyberMon/site/js/editorial.js:1666). Evidence: step 11.

### 9. P2 — Source provenance disappears from the Field footer

A comma after the conditional Changed lately string terminates the assignment expression. Everything after it, including dataset dates, build time, and methodology links, is evaluated but not appended.

**Observed:** the live rail ends after the change counts. **Fix:** replace the comma with the intended concatenation and assert that source versions and generation time appear.

Source: [field.js:960](D:/DEV/CyberMon/site/js/field.js:960). Evidence: step 8 and `field-dom.txt`.

### 10. P2 — Additive blending overwhelms the colour encoding

Large populations turn into white/yellow patches. In the CNA and CWE views, dense piles lose the distinction between ordinary records, PoCs, and KEV points. The timeline also saturates recent cohorts.

**Fix:** use density-aware opacity/aggregation at overview zoom, a controlled brightness ceiling, and a separate KEV overlay. Offer an analytical 2D projection. Preserve individual points when zooming into a manageable region.

Source: [field.js:225](D:/DEV/CyberMon/site/js/field.js:225). Evidence: steps 2–7.

### 11. P2 — Label collisions and overlay overlap impede reading

Vendor and CWE labels overlap adjacent groups at the default desktop camera. The clock's rightmost PoC label is clipped. In the grid view the thesis overlaps the EPSS-axis region. Timeline CVSS zero/no-score labels collide.

**Fix:** reserve space for copy, apply screen-space label collision management to all labels, shorten group labels with full names on focus, and fit the camera to the actual layout plus labels. The new `thinTicks()` only addresses year/month labels.

Source: [field.js:433](D:/DEV/CyberMon/site/js/field.js:433), [field.js:777](D:/DEV/CyberMon/site/js/field.js:777). Evidence: steps 2–6.

### 12. P2 — Mobile reflow does not fit the instrument

At 390 px, the header thesis wraps into a narrow column. The desktop camera clips both ends of the timeline and several axis labels. Controls are below the visualization; lower controls require scrolling away from the result, then back up to see their effect.

**Fix:** use a compact mobile header, calculate a camera fit from aspect ratio, and provide a sticky compact controls bar or drawer while keeping the visualization visible. Include touch-specific instructions.

Source: [field.css:384](D:/DEV/CyberMon/site/css/field.css:384), [field.js:871](D:/DEV/CyberMon/site/js/field.js:871). Evidence: step 8. Physical pinch behavior was not verified.

### 13. P2 — Individual records have no keyboard-accessible alternative

The controls have labels, but the canvas is not keyboard navigable. Record inspection, camera movement, and box selection depend on pointing. A canvas description and aggregate counters do not expose individual records or relationships. On touch, a tap opens the external record instead of first presenting its in-site details.

**Fix:** add a searchable result table/list synchronized with filters and selection, keyboard camera/selection commands, and a persistent record inspector that opens external sources only through an explicit link. Test with keyboard and a screen reader.

Source: [field.html:116](D:/DEV/CyberMon/site/field.html:116), [field.js:645](D:/DEV/CyberMon/site/js/field.js:645), [field.js:754](D:/DEV/CyberMon/site/js/field.js:754).

### 14. P2 — Vendor search silently loses the long tail

The binary retains only the 1,023 most frequent vendor names; all remaining known names become “other.” Those records cannot be retrieved by their vendor name, and the vendor arrangement excludes them altogether. The rail describes placeholders/missing vendors but does not disclose this name truncation.

**Fix:** preserve the full vendor dictionary where feasible (the field already uses u16), or publish explicit omitted-known-vendor counts and a search limitation. Distinguish missing vendor from omitted vendor. Normalizing company aliases would be a separate, versioned data task.

Source: [field_export.py:67](D:/DEV/CyberMon/pipeline/field_export.py:67), [field_export.py:247](D:/DEV/CyberMon/pipeline/field_export.py:247), [field.js:319](D:/DEV/CyberMon/site/js/field.js:319).

### 15. P2 — Sort changes which groups exist, despite “largest” wording

Sorting by name happens before slicing the groups. It shows the alphabetically first 48 assigners/vendors or 30 weaknesses, rather than sorting the largest groups. The thesis still describes the largest groups by volume.

**Fix:** choose the top-N population separately from its display order, or label the selection rule dynamically. Make the excluded population explicit.

Source: [field.js:438](D:/DEV/CyberMon/site/js/field.js:438), [field.js:463](D:/DEV/CyberMon/site/js/field.js:463).

### 16. P2 — Point-size-only changes are missing from shared links

`writeHash()` supports point size, but the size input listener calls only `colour()`. Copying the URL immediately after moving this slider omits the change. This was reproduced live. Camera and selection state are never serialized, so “the view” is only partially shareable even after the slider fix.

**Fix:** write the hash after size changes, document exactly what is shared, and optionally serialize camera/selection recipes plus edition ID.

Source: [field.js:832](D:/DEV/CyberMon/site/js/field.js:832), [field.js:935](D:/DEV/CyberMon/site/js/field.js:935).

### 17. P2 — Selection median is wrong for even populations

The code uses `scores[Math.floor(length / 2)]`, returning the upper middle score. For two scores 4.0 and 8.0 it reports 8.0 rather than 6.0.

**Fix:** average the two middle values for even populations; test empty, odd, and even selections.

Source: [field.js:612](D:/DEV/CyberMon/site/js/field.js:612). Source-confirmed edge case; the full live selection had an odd scored population.

### 18. P2 — Idle frames keep doing unnecessary work

The renderer schedules another frame unconditionally, draws all points, projects labels, writes DOM positions, and filters labels even when nothing changes. This continues under reduced-motion preference. The picking pass also still draws the full cloud; it is not constant total work in record count despite the source comment.

**Fix:** render on invalidation, keep animation frames only during motion, pause work when the document is hidden, and measure interaction latency on representative GPUs. This is an implementation finding, not a measured frame-rate claim.

Source: [field.js:761](D:/DEV/CyberMon/site/js/field.js:761).

### 19. P2 — The new instrument is outside the browser regression gate

`tools/site_smoke.py` explicitly lists standard pages but omits `field.html`. Its existing footer assertion also cannot simply be reused for the Field. Python exporter tests do not catch the stale selection, missing source text, or CDN initialization failure.

**Fix:** add a small built Field fixture and a dedicated browser scenario suite for boot, arrangements/counts, threshold parity, time cuts plus selection, share-state round trips, keyboard access, and failure states. Check the assembled deployment artifact as well as the checkout.

Source: [site_smoke.py:38](D:/DEV/CyberMon/tools/site_smoke.py:38), [ci.yml:54](D:/DEV/CyberMon/.github/workflows/ci.yml:54).

### 20. P2 — Field discovery and investigation are unnecessarily difficult

The overview's initial desktop screen is largely masthead and navigation. The Field appears after all 21 module cards and has no global instrument link. Inside the instrument there is no visible CVE-ID search, reset-all-filters, or useful empty-results recovery. Users are instructed to edit the URL to focus a CVE. Box selection produces aggregate summaries but no member list or export.

**Fix:** promote Instruments near the overview start, provide a global Field link, add CVE search and reset filters, and expose selected members with a download/share action. These are product gaps observed in the reviewed UI, not broken existing promises.

Source: [home.js](D:/DEV/CyberMon/site/js/home.js), [field.html](D:/DEV/CyberMon/site/field.html). Evidence: steps 1, 8, 9.

### 21. P2 — Binary/metadata pairing is only size-checked

The metadata and binary use stable filenames and are fetched separately. The reader checks decompressed length, but neither a content hash nor embedded edition identifier. Across a deployment boundary, mismatched files of the same length could decode successfully with wrong dictionary indices.

**Fix:** content-address the binary filename and validate its hash/edition. This is a source-based deployment race risk; no mismatch was observed during this review.

Source: [field.js:140](D:/DEV/CyberMon/site/js/field.js:140), [field_export.py:92](D:/DEV/CyberMon/pipeline/field_export.py:92).

### 22. P3 — A few control and explanatory details remain misleading

- Non-exploitation colour legends append a red KEV swatch even though KEV points retain that mode's colour; only size marks KEV. Show a size legend instead (`field.js:550`).
- The Field's noscript copy says the charted version exposes numbers without scripts, but `cve.html` constructs its chart sections with JS. Link directly to readable data or prerender a summary (`field.html` noscript).
- The first/last-year sliders can cross; state is swapped but the input values are not updated, contradicting their accessible first/last labels (`field.js:882`).
- `first_day` is taken from the first row sorted by CVE-ID, not the minimum publication day. It is misleading metadata even though today's UI does not use it (`field_export.py` metadata assembly).
- Changed lately highlights records without putting the changed flag, direction, date, or old/new value into the record card. Add the reason to the inspector; the current binary only retains two booleans (`field.js:731`).

## Further checks worth doing

These are deliberately not promoted to reproduced defects: physical two-finger gesture behavior, WebGL context loss/recovery, picking accuracy at different device-pixel ratios, and shader ID-buffer hit footprints. The half-resolution picking target reuses the full-size point shader, so its effective hit area deserves a pixel-level comparison. Test Safari/Firefox and low-end devices before making compatibility or performance claims.

## Suggested order of work

1. Correct count masks, selection/time cuts, EPSS bucket parity, source footer, CDN boot, and deployment artifact retrieval.
2. Correct historical and scoring language; qualify the EPSS grade.
3. Add the dedicated Field regression suite and validate a built deployment artifact.
4. Improve mobile camera fit, label placement, density rendering, and accessible record inspection.
5. Promote the Field and add search/export; then build another instrument on the improved shared foundation.

## Screenshot walkthrough

1. **Overview — operational; discovery weak.** Navigation works, but the instrument is buried below the module catalogue.

![Overview](D:/DEV/CyberMon/docs/review-2026-09-10/index-viewport.png)

2. **Timeline — operational; dense encoding and axis collisions.** All records load; white saturation conceals categorical colour.

![Timeline](D:/DEV/CyberMon/docs/review-2026-09-10/field-desktop.png)

3. **Score grid — operational; interpretation and bucket accuracy need correction.** The explanatory overlay also competes with the axis.

![Score grid](D:/DEV/CyberMon/docs/review-2026-09-10/grid-desktop.png)

4. **Assigner — misleading totals and crowded labels.** Header and placed-group population differ.

![Assigner](D:/DEV/CyberMon/docs/review-2026-09-10/cna-desktop.png)

5. **Vendor — misleading totals and overlapping names.** Normalized spellings still split companies; long names collide.

![Vendor](D:/DEV/CyberMon/docs/review-2026-09-10/vendor-desktop.png)

6. **Weakness — misleading totals and label collisions.** The untagged population dominates and saturates.

![Weakness](D:/DEV/CyberMon/docs/review-2026-09-10/cwe-desktop.png)

7. **Clock and NVD status — load successfully; legibility needs work.** Clock excludes records without dated events, as disclosed. It displays one event per CVE, so records with both events contribute only to the KEV lane; connected two-event timelines would be a useful future enhancement. NVD grouping is readable relative to the denser group views, though large piles still saturate.

![Clock](D:/DEV/CyberMon/docs/review-2026-09-10/clock-desktop.png)

![NVD status](D:/DEV/CyberMon/docs/review-2026-09-10/status-desktop.png)

8. **Mobile — renders, but the default camera and controls arrangement impair use.** No persistent page-width overflow was established; the visible axis clipping occurs inside the canvas.

![Mobile Field](D:/DEV/CyberMon/docs/review-2026-09-10/field-mobile.png)

9. **Selection followed by time cut — incorrect receipt.** This empty January 1999 view still claims the entire corpus is selected.

![Stale selection](D:/DEV/CyberMon/docs/review-2026-09-10/selection-time-cut.png)

10. **Failure and sharing checks — confirmed failures.** No useful screenshot exists for a library that never initializes; the exact JavaScript error and absent notice are in `field-checks.json`. Point-size URL persistence also failed.

11. **Other module scan / EPSS inspection — loading healthy; forecast interpretation needs revision.** All 22 standard pages passed the live load checks. The selected EPSS screen makes the stronger methodological claim discussed above.

![EPSS framing](D:/DEV/CyberMon/docs/review-2026-09-10/epss-viewport.png)

## Evidence files

- `live-pages.json`: per-page load/error checks. Its immediate post-resize mobile flags are transient and superseded by the settled checks described above.
- `field-checks.json`: binary counts and browser reproductions. Byte-equality false values reflect CRLF/LF differences; normalized equality is confirmed in the next file.
- `extra-checks.json`: normalized deployed source equality and same-edition bucket discrepancies.
- `field-dom.txt`: Field visible text including the truncated source footer.
- The Python scripts alongside this report reproduce the review checks; they are audit helpers, not newly integrated application tests.
