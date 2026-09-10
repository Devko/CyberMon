# CyberMon review fixes — 10 September 2026

The 22 grouped findings in REVIEW.md have been addressed in the local source. The live GitHub Pages deployment has not been changed.

| Review findings | Changes |
| --- | --- |
| 1–2: population counts and stale selections | Separate matching, placed, and month-visible populations; counters, group labels, selections, and exports use the same visible population. Month changes clear selections. |
| 3: EPSS bucket disagreement | Field layout v4 stores the bucket computed from the raw probability separately from the rounded display value. Threshold tests compare the exporter with the chart classifier. |
| 4–5: deployment and boot failures | Artifact retrieval skips successful no-op runs, validates data, and fails deployment when no valid artifact exists. Missing Three.js produces the intended notice. |
| 6–8: analytical claims | Publication playback explicitly uses edition attributes; severity and predicted exploitation are distinct dimensions; EPSS before KEV listing is described as a cohort observation, without claiming forecast calibration or accuracy. |
| 9: provenance | Restored source versions, generation time, and methodology links in the footer. |
| 10–12: display and mobile | Replaced additive blending with normal blending, added a separate KEV drawing pass, a flat projection, collision-managed labels, an aspect-aware camera, separate explanatory space, and a mobile controls drawer. |
| 13: record accessibility | Added keyboard camera controls, Select shown, searchable paginated records, and a persistent inspector with an explicit external source link. |
| 14–15: vendor retention and sorting | Preserve the full vendor dictionary within the u16 limit and reject overflow; choose largest groups before sorting their display order. |
| 16–17: sharing and statistics | Point size is saved immediately in the URL; documented shared-state scope; corrected the median for even populations. |
| 18–19: rendering and regression gates | Render on invalidation, stop publication playback when hidden, and add dedicated fixture and assembled-artifact Field browser gates. |
| 20: discovery and investigation | Promoted the Field on the overview and shared navigation; added CVE search, reset, empty-state recovery, member browsing, and JSON exports with edition information. |
| 21: data pairing | Content-addressed binary filenames and SHA-256 verification in the browser and deployment helper. Sample data is rejected for deployment. |
| 22: explanatory details | Corrected KEV size legends, no-script data links, crossed year inputs, earliest-publication metadata, and changed-record explanations in the inspector. |

## Verification

- Pipeline: 1,268 passed, 1 skipped. One existing pytest deprecation warning remains.
- Standard-site browser check: all 22 pages passed.
- Field browser fixture: 72 records; arrangement totals, top-group sorting, drag selection, time-cut clearing, exact thresholds, even median, keyboard inspection, search, JSON download, URL state, mobile width, idle rendering, missing-library handling, and corrupt-blob rejection passed.
- Scale check: 348,844 records and 22,319 vendor dictionary entries passed the assembled Field browser suite. Desktop timeline, grid, assigner, and mobile screenshots were inspected. This isolated sample uses a local July archive and joins from local data; it is a scale/visual test, not a newly fetched production edition.
- Offline pipeline build with Field output passed.
- Motion preflight: all three scenes passed nonblank/distinct-frame checks after correcting a duplicate shared-navigation declaration found during final verification.
- Patch whitespace check passed.

## Deployment and limits

Run the nightly workflow manually on the updated revision to generate and publish the version-4 Field. The frontend intentionally rejects old layouts, and push deployment intentionally fails until a valid v4 artifact is available. No production workflow was triggered during this work, and isolated fixtures were not copied into production data.

Browser checks used headless Chromium. Physical touch devices, screen-reader usability, Firefox/Safari, and representative low-end GPUs still need manual acceptance testing. Labels that cannot fit are suppressed until camera movement or zoom creates space; this is not an aggregate density renderer. The binary retains change flags, not historical old/new values, and URL sharing does not preserve a camera or selection snapshot.
