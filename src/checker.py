# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Offline Sharp/librsvg evidence assessment; never imports Sharp or decodes images."""

import argparse
import sys

TOOL_NAME = "sharp-rsvg-rce-check"
TOOL_VERSION = "0.1.0"
RULE_ID = "CVE-2026-96889"
RULE_DATE = "2026-10-24"
SNAPSHOT_ID = "sharp-rsvg-2026-10-24.1"
ADVISORY_URL = "https://github.com/lovell/sharp/security/advisories/GHSA-wq5f-xc86-pv6w"
SOURCES = [ADVISORY_URL, "https://github.com/advisories/GHSA-wq5f-xc86-pv6w"]
MAX_RECORDS = 1000
PROVENANCE = ("upstream", "vendor", "custom", "unknown")
OBSERVED = ("present", "absent", "unknown", "conflicting")
DEFAULTS = {
    "sharp_versions": [], "librsvg_versions": [], "library_source": "unknown",
    "sharp_build_source": "unknown", "librsvg_build_source": "unknown",
    "platform": "unknown", "libc": "unknown", "node_pie": "unknown",
    "svg_decoder": "unknown", "untrusted_svg": "unknown",
}
RECORD_SCHEMA = _object({
    "asset_id": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?![\s\S])", "maxLength": 64},
    "sharp_versions": _array(_text(64, min_length=1), 8),
    "librsvg_versions": _array(_text(64, min_length=1), 8),
    "library_source": _enum(("bundled", "global", "unknown")),
    "sharp_build_source": _enum(PROVENANCE), "librsvg_build_source": _enum(PROVENANCE),
    "platform": _enum(("linux", "other", "unknown")),
    "libc": _enum(("glibc", "musl", "other", "unknown")),
    "node_pie": _enum(("enabled", "disabled", "unknown", "conflicting")),
    "svg_decoder": _enum(("enabled", "blocked", "unknown", "conflicting")),
    "untrusted_svg": _enum(OBSERVED),
}, required=["asset_id"])
INPUT_SCHEMA = _object({"schema_version": {"const": "1.0"},
                        "records": _array(RECORD_SCHEMA, MAX_RECORDS, 1)})
LIMITATIONS = [
    "Offline operator-supplied evidence only; library selection, deployed versions, provenance and effective mitigations are not independently attested.",
    "No network requests, application execution, image decoding, exploitation, reachability test or compromise detection is performed.",
    "The Sharp comparison covers exact stable 0.0-0.35 versions. Global librsvg has a documented remediation build, not a published independent affected-version range; only stable 2.63.2+ within 2.63 is accepted as reported remediation.",
    "PIE is an RCE mitigation, not a library patch or a guarantee against other memory-corruption impact. Unknown libc or PIE remains unknown.",
]
RECOMMENDATION = (
    "For official bundled binaries, upgrade Sharp to 0.35.5 or a later supported patched release. "
    "For a global library, independently verify the selected librsvg and apply the upstream 2.63.2 fix or a documented vendor fix. "
    "Rebuild/redeploy and verify the actual linkage. Effective VipsForeignLoadSvg blocking and Node PIE are separate mitigations; neither attests the library patch set."
)


def normalize_record(record):
    validate_schema(record, RECORD_SCHEMA)
    return {**deepcopy(DEFAULTS), **deepcopy(record)}


def read_inventory(path):
    data = load_json(path)
    validate_schema(data, INPUT_SCHEMA)
    records = [normalize_record(record) for record in data["records"]]
    if len({record["asset_id"] for record in records}) != len(records):
        raise ContractError("duplicate asset identifiers")
    return records


def exact_version(value):
    if not isinstance(value, str) or len(value) > 32:
        return None
    match = re.fullmatch(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", value)
    return tuple(int(part) for part in match.groups()) if match else None


def version_observation(values):
    """Repeated equal observations agree; ranges, qualifiers and conflicts do not."""
    if not values:
        return None, None, "unknown"
    if len(set(values)) > 1:
        return None, None, "conflicting"
    value = values[0]
    parsed = exact_version(value)
    return (value, parsed, "present") if parsed else (None, None, "unknown")


def version_state(record):
    """Assess only the selected component; a Sharp version cannot clear a global library."""
    sharp, sharp_tuple, sharp_state = version_observation(record["sharp_versions"])
    rsvg, rsvg_tuple, rsvg_state = version_observation(record["librsvg_versions"])
    source = record["library_source"]
    if source == "bundled":
        component, version, provenance, observed = "Sharp (bundled librsvg)", sharp, record["sharp_build_source"], sharp_state
        state, reason = "unknown", "Bundled Sharp evidence is missing, malformed or conflicting."
        if sharp_tuple is not None:
            if provenance != "upstream":
                reason = "Bundled Sharp provenance is unknown, vendor or custom; an upstream version cannot attest its patch set."
            elif sharp_tuple[0] != 0 or sharp_tuple[1] > 35:
                reason = "The reported Sharp release line is outside this snapshot."
            else:
                state = "affected" if sharp_tuple < (0, 35, 5) else "fixed_reported"
                reason = "The reported official Sharp bundle is below 0.35.5." if state == "affected" else "The reported official Sharp bundle meets the 0.35.5 fix threshold."
                if record["librsvg_versions"]:
                    if rsvg_tuple is None or record["librsvg_build_source"] != "upstream" or rsvg_tuple[:2] != (2, 63):
                        state, reason = "unknown", "Additional librsvg evidence is conflicting, qualified, outside the reviewed release line or lacks upstream provenance."
                    elif (rsvg_tuple >= (2, 63, 2)) != (state == "fixed_reported"):
                        state, reason = "unknown", "Sharp and librsvg patch observations disagree; possible overrides or backports require independent review."
    elif source == "global":
        component, version, provenance, observed = "librsvg (global, used by Sharp)", rsvg, record["librsvg_build_source"], rsvg_state
        state, reason = "unknown", "Global selection requires independent exact librsvg version and build provenance; the Sharp package version cannot establish this."
        if rsvg_tuple is not None and provenance == "upstream":
            if rsvg_tuple[:2] == (2, 63) and rsvg_tuple >= (2, 63, 2):
                state, reason = "fixed_reported", "The independently reported global librsvg meets the documented 2.63.2 remediation build in the reviewed 2.63 line."
            else:
                reason = "Global librsvg is below the documented remediation build or outside its reviewed release line; the advisory provides no independent affected-version range."
        if record["sharp_versions"] and sharp_state != "present":
            state, reason = "unknown", "Additional Sharp version evidence is malformed or conflicting; verify that all evidence belongs to the same deployment."
    else:
        component, version, provenance, observed = "Sharp librsvg selection", None, "unknown", "unknown"
        state, reason = "unknown", "Library selection is unknown; a patched Sharp package cannot establish the version of a possible global librsvg."
    return component, version, provenance, observed, state, reason


def assess_record(raw):
    record = normalize_record(raw)
    component, version, provenance, observed, assessed, reason = version_state(record)
    evidence = [{"id": "selected-version", "kind": "version", "state": observed,
                 "detail": reason},
                {"id": "library-selection", "kind": "inventory", "state": "unknown" if record["library_source"] == "unknown" else "present",
                 "detail": "Operator-reported library selection: " + record["library_source"] + "; linkage is not independently verified."}]
    for key, label in (("sharp_versions", "Sharp"), ("librsvg_versions", "librsvg")):
        value, _, state = version_observation(record[key])
        evidence.append({"id": key.replace("_", "-"), "kind": "inventory", "state": state,
                         "detail": label + " version observation: " + (value if value else "missing, qualified or conflicting") + "."})
    platform, libc = record["platform"], record["libc"]
    glibc = "absent" if platform == "other" or (platform == "linux" and libc in {"musl", "other"}) else "present" if platform == "linux" and libc == "glibc" else "unknown"
    states = {
        "glibc-linux": glibc,
        "svg-decoding": {"enabled": "present", "blocked": "absent"}.get(record["svg_decoder"], record["svg_decoder"]),
        "node-without-pie": {"disabled": "present", "enabled": "absent"}.get(record["node_pie"], record["node_pie"]),
        "untrusted-svg-input": record["untrusted_svg"],
    }
    details = {
        "glibc-linux": "Reported platform: " + platform + "; reported libc: " + libc + ". Other platforms do not establish that the underlying memory bug is absent.",
        "svg-decoding": "Reported effective SVG decoder state: " + record["svg_decoder"] + ". A blocked claim must cover VipsForeignLoadSvg in the deployed process.",
        "node-without-pie": "Reported Node executable PIE state: " + record["node_pie"] + ". No binary inspection is performed.",
        "untrusted-svg-input": "Operator-reviewed untrusted SVG input path: " + record["untrusted_svg"] + ". No data-flow or reachability test is performed.",
    }
    preconditions = []
    for key, state in states.items():
        evidence.append({"id": key, "kind": "configuration", "state": state, "detail": details[key]})
        preconditions.append({"id": key, "state": state, "evidence_ids": [key]})
    mitigation_ids = []
    for key, present, detail in (
        ("svg-block", record["svg_decoder"] == "blocked", "Effective VipsForeignLoadSvg blocking is operator-reported; this is a decoder mitigation, not a patch attestation."),
        ("node-pie", record["node_pie"] == "enabled", "Node PIE is operator-reported; it mitigates the documented RCE condition, not other memory-corruption impacts or library patch state."),
    ):
        if present:
            mitigation_ids.append(key)
            evidence.append({"id": key, "kind": "configuration", "state": "present", "detail": detail})
    mitigation = {"state": "observed" if mitigation_ids else "unknown", "evidence_ids": mitigation_ids}
    status = "unknown"
    if assessed == "fixed_reported":
        status = "fixed_version_reported"
    elif assessed == "affected":
        status = "mitigated_configuration" if mitigation_ids else "precondition_present" if all(value == "present" for value in states.values()) else "potentially_affected"
    return make_result(record["asset_id"], component, RULE_ID, status, version=version,
                       build_source=provenance, version_assessment=assessed, evidence=evidence,
                       preconditions=preconditions, mitigation=mitigation,
                       confidence="low" if assessed != "unknown" else "unknown",
                       reasons=[reason, "Version, platform, libc, effective mitigation and input-path observations are operator claims; local exploitability remains not_tested.",
                                "A mitigated configuration preserves an affected library/package assessment and does not establish safety or absence of prior compromise."],
                       recommendation=RECOMMENDATION, sources=SOURCES)


def publish_results(args, results, protected, *, complete):
    report = make_report(TOOL_NAME, TOOL_VERSION, SNAPSHOT_ID, RULE_DATE, results,
                         complete=complete, limitations=LIMITATIONS,
                         snapshot_digest=snapshot_digest(RULE_SNAPSHOT))
    rendered = canonical_json(report) if args.format == "json" else render_csv(report) if args.format == "csv" else render_html(report, brand=args.brand, logo=args.logo)
    if args.output:
        save_report(args.output, rendered, force=args.force, protected_paths=protected)
    else:
        sys.stdout.write(rendered)


def build_parser():
    parser = argparse.ArgumentParser(description="Offline CVE-2026-96889 Sharp/librsvg evidence assessment. No network, application execution or image decoding.")
    parser.add_argument("--inventory", type=Path, help="Bounded schema-v1 JSON inventory; cannot be combined with per-asset options.")
    parser.add_argument("--sharp-version", action="append", dest="sharp_versions", help="Reported stable Sharp version; repeat to preserve conflicts.")
    parser.add_argument("--librsvg-version", action="append", dest="librsvg_versions", help="Independently reported native librsvg version; repeat to preserve conflicts.")
    parser.add_argument("--asset-id", help="Opaque identifier, at most 64 ASCII letters/digits/dot/underscore/hyphen; default asset-0001.")
    parser.add_argument("--library-source", choices=("bundled", "global", "unknown"), help="Selected deployed native library; default unknown.")
    parser.add_argument("--sharp-build-source", choices=PROVENANCE, help="Reported Sharp build provenance; default unknown.")
    parser.add_argument("--librsvg-build-source", choices=PROVENANCE, help="Independent native-library provenance; default unknown.")
    parser.add_argument("--platform", choices=("linux", "other", "unknown"))
    parser.add_argument("--libc", choices=("glibc", "musl", "other", "unknown"))
    parser.add_argument("--node-pie", choices=("enabled", "disabled", "unknown", "conflicting"))
    parser.add_argument("--svg-decoder", choices=("enabled", "blocked", "unknown", "conflicting"))
    parser.add_argument("--untrusted-svg", choices=OBSERVED)
    parser.add_argument("--format", choices=("json", "csv", "html"), default="json")
    parser.add_argument("--output", type=Path, help="New report path; stdout if omitted.")
    parser.add_argument("--force", action="store_true", help="Replace an existing report, never an input or scanner.")
    parser.add_argument("--brand", default="CompleteTech LLC", help="Escaped HTML report display name.")
    parser.add_argument("--logo", type=Path, help="Optional bounded local raster logo, only with HTML.")
    parser.add_argument("--fail-on-finding", action="store_true", help="Exit 1 for every affected version, including a mitigated configuration.")
    parser.add_argument("--fail-on-unknown", action="store_true", help="Exit 1 for unknown version state or unresolved conditions on an affected version.")
    parser.add_argument("--version", action="version", version=TOOL_VERSION)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    selected = {key: getattr(args, key) for key in RECORD_SCHEMA["properties"] if getattr(args, key, None) is not None}
    if args.inventory and selected:
        parser.error("--inventory cannot be combined with per-asset options")
    if not args.inventory and not (args.sharp_versions or args.librsvg_versions):
        parser.error("provide --inventory, --sharp-version or --librsvg-version")
    results, protected = [], [Path(__file__)]
    if args.inventory:
        protected.append(args.inventory)
    if args.logo:
        protected.append(args.logo)
    try:
        if args.logo and args.format != "html":
            raise ContractError("logo requires HTML output")
        if args.inventory:
            records = read_inventory(args.inventory)
        else:
            records = [normalize_record({"asset_id": "asset-0001", **selected})]
        for record in records:
            results.append(assess_record(record))
        publish_results(args, results, protected, complete=True)
        if args.fail_on_finding and any(result["version_assessment"] == "affected" for result in results):
            return 1
        if args.fail_on_unknown and any(result["version_assessment"] == "unknown" or (result["version_assessment"] == "affected" and any(condition["state"] in {"unknown", "conflicting"} for condition in result["preconditions"])) for result in results):
            return 1
        return 0
    except KeyboardInterrupt:
        try:
            publish_results(args, results, protected, complete=False)
            sys.stderr.write("Assessment interrupted; completed results preserved in an incomplete report.\n")
        except (ValueError, OSError, KeyboardInterrupt):
            sys.stderr.write("Assessment interrupted; incomplete report could not be written.\n")
        return 130
    except (ValueError, OSError):
        sys.stderr.write("Assessment failed: invalid or excessive evidence, unavailable file, protected output, or report validation error.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
