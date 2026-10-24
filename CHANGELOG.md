# Changelog

## 0.1.0 — 2026-10-24

- Implement offline Sharp/librsvg evidence assessment for CVE-2026-96889.
- Separate official bundles, independently evidenced global libraries, build provenance, platform/libc, SVG input paths, loader blocking and Node PIE.
- Preserve unknown/conflicting evidence, affected versions under mitigation, and `exploitability: not_tested`.
- Add bounded schema-v1 inventory, JSON/CSV/offline HTML, protected reports and interruption recovery.
- Add a deterministic standalone build, source-linked snapshot, synthetic tests and six-job Python CI.
