# Implementation and release checklist

**sharp-rsvg-rce-check · CVE-2026-96889 · offline evidence implementation**

The original research foundation is preserved in Git history and `advisory.json`'s research-origin fields. The implementation follows the repository's one-exploit scope and the shared evidence/reporting contract.

- [x] Re-read the primary maintainer and GitHub advisories on 2026-10-24; record the exact Sharp threshold and the native-library remediation caveat.
- [x] Keep the alias, product, bundled/global selection, provenance and covered release lines explicit.
- [x] Implement a standalone Python 3.10+ executable with a bounded schema-v1 offline inventory and explicit per-asset CLI inputs.
- [x] Perform no network requests, application imports/execution, package-manager operations, image decoding or exploit probes.
- [x] Keep missing, conflicting, malformed, vendor/custom, prerelease, possible-backport and uncovered-future evidence unknown.
- [x] Separate the version assessment, glibc/Linux conditions, SVG input path, decoder block, Node PIE and local exploitability.
- [x] Provide validated JSON, formula-neutralized CSV and escaped script-free HTML, a rule digest, deterministic outputs, controlled errors and protected atomic report publication.
- [x] Preserve completed results during a handled interruption with `complete=false`; keep finding and unknown gates separate.
- [x] Add synthetic boundary, ambiguity, mitigation, input-limit, standalone, interruption and report-protection behavior tests.
- [x] Add Python 3.10/3.14 CI on Linux, Windows and macOS, including deterministic build checks and documented commands.
- [x] Replace pending README claims with actual commands and link an actual synthetic HTML report. Retained concept images are not presented as generated output.
- [ ] Complete independent review and verify hosted CI for the exact final PR commit before merge.

No real system was assessed during implementation. Local verification, hosted CI and independent review are separate evidence. A rule enabled in this implementation does not establish live exposure, exploitation or production readiness.
