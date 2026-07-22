# Design QA

## Comparison target

- Source visual truth: `https://claude.ai/code/artifact/6d21c369-b9d6-482c-a261-267d6fa87da1`.
- Source captures: `docs/evidence/design-qa/source-overview.jpg` and `docs/evidence/design-qa/source-evidence.png`.
- Browser-rendered implementation captures: `docs/evidence/design-qa/implementation-scan.png` and `docs/evidence/design-qa/implementation-result.png`.
- Full-view comparison input: `docs/evidence/design-qa/comparison-overview.jpg`.
- Focused evidence/result comparison input: `docs/evidence/design-qa/comparison-evidence.jpg`.
- Responsive evidence: `docs/evidence/design-qa/implementation-mobile.png` contains the public scan journey in a 360 x 800 CSS-pixel frame.
- Desktop viewport: 1280 x 720 CSS pixels for both source and implementation.
- Captured source and implementation pixels: 1280 x 720 each. The in-app browser reported device pixel ratio 2 and normalized both screenshots to the same 1280 x 720 output before comparison.
- State: public light theme; source brand, component and evidence guidance compared with the initial scan journey and a completed real local-only result.

## Findings

No actionable P0, P1 or P2 differences remain.

- Fonts and typography: IBM Plex Sans and IBM Plex Mono match the supplied families and roles. Display, heading, body, support, label and evidence text retain the source hierarchy without truncation at the tested breakpoints.
- Spacing and layout rhythm: the 4-pixel scale, restrained grid, 6/9/12-pixel radii, hairlines and quiet elevation are consistent with the source. Desktop and 360-pixel layouts have no horizontal overflow or obscured primary controls.
- Colors and visual tokens: cobalt is reserved for brand, selection and action; green, amber, red and slate remain semantic risk colors paired with text and distinct icons. Neutral surfaces and contrast match the source direction.
- Image and asset fidelity: the supplied shield-and-hook mark is used as the real SVG asset. Interface icons come from the selected icon library; no visible source asset was replaced by a placeholder, emoji or CSS drawing.
- Copy and content: the product keeps the source's calm, evidence-first language. It says when data is missing, calls local-only the default, redacts query/path details, never labels a URL “safe,” and never provides an action that opens the submitted target.

## Full-view comparison evidence

`docs/evidence/design-qa/comparison-overview.jpg` places the source system and implementation scan journey in one matched 1280 x 720 comparison. The implementation carries through the same neutral field, cobalt discipline, IBM Plex hierarchy, compact radii, quiet borders and evidence-first composition. The implementation intentionally turns the design-system document into a task-focused product screen rather than duplicating its documentation layout.

## Focused-region comparison evidence

`docs/evidence/design-qa/comparison-evidence.jpg` places the source evidence-pattern section and the real local-only result in one matched comparison. Redacted URL treatment, semantic status chips, provenance-oriented disclosure, missing-evidence honesty, icon-plus-text risk communication and restrained card styling remain legible at this scale, so no additional crop was required.

## Comparison history

1. The first result comparison found a P1 truthfulness issue: development fallback data could be mistaken for a live assessment and included observations that had not been collected. The fallback was changed to show a persistent simulated-data banner, `RULE_ONLY` mode, and unavailable rather than fabricated provider/destination evidence. Post-fix evidence: `docs/evidence/design-qa/iteration-simulated-banner.png`.
2. The first result comparison also found a P2 communication issue: a numeric score implied more decision precision than the governed risk bands support. The score was removed from the public contract and interface while the internal probability remains available to versioned decision logic. Earlier evidence: `docs/evidence/design-qa/iteration-score-before.jpg`; post-fix evidence: `docs/evidence/design-qa/implementation-result.png`.
3. The final matched pass found no actionable P0, P1 or P2 mismatch. Evidence: `docs/evidence/design-qa/comparison-overview.jpg` and `docs/evidence/design-qa/comparison-evidence.jpg`.

## Interaction and runtime checks

- Submitted a real local-only scan through the containerized FastAPI/PostgreSQL application and reached the completed result route.
- Expanded technical details and verified policy, ruleset, model, scope, completion and engine-mode disclosure.
- Opened and closed the native share-report dialog without creating an external share.
- Verified the initial journey at 360 pixels, including navigation, mode selection and primary action.
- Checked the final real-result browser tab for console errors; none were present.

## Residual test gaps

Manual screen-reader testing, contrast measurement across every role workspace and testing on physical mobile devices remain part of academic acceptance, as recorded in the traceability matrix. They do not represent visible P0/P1/P2 mismatches in this browser comparison.

final result: passed
