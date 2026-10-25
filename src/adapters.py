# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Bounded metadata adapters. These observations never attest runtime selection."""
import struct


def adapter_path(path, root):
    relative = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    validate_schema(relative, {"type": "string", "format": "relative-path", "maxLength": 512})
    return relative


def adapter_result(asset_id, component, evidence, *, version=None):
    return make_result(asset_id, component, RULE_ID, "unknown", version=version,
                       version_assessment="unknown", build_source="unknown", evidence=evidence,
                       reasons=["File metadata and lexical source candidates do not establish deployed library selection, build provenance or runtime conditions."],
                       recommendation=RECOMMENDATION, sources=SOURCES)


def inspect_elf(path):
    """Inspect at most 64 + 57,344 + 512 bytes, never map/load/execute an ELF."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024**3:
            raise ContractError("ELF must be a bounded regular file")
        header = stream.read(64)
        if len(header) < 16 or header[:4] != b"\x7fELF" or header[4] not in {1, 2} or header[5] not in {1, 2} or header[6] != 1:
            raise ContractError("Unsupported ELF identification")
        bits, endian = header[4], "<" if header[5] == 1 else ">"
        fmt = endian + ("HHIIIIIHHHHHH" if bits == 1 else "HHIQQQIHHHHHH")
        size = 16 + struct.calcsize(fmt)
        if len(header) < size:
            raise ContractError("Truncated ELF header")
        fields = struct.unpack_from(fmt, header, 16)
        file_type, _, version, _, offset, _, _, ehsize, entry_size, count, *_ = fields
        expected = 32 if bits == 1 else 56
        if version != 1 or ehsize != size or count > 1024 or (count and entry_size != expected):
            raise ContractError("Unsupported ELF header layout")
        if count and (offset < size or offset + count * entry_size > info.st_size):
            raise ContractError("ELF program header table is outside the file")
        if count:
            stream.seek(offset)
        program_headers = stream.read(count * entry_size)
        if len(program_headers) != count * entry_size:
            raise ContractError("Truncated ELF program headers")
        interpreter = None
        for index in range(count):
            ph = struct.unpack_from(endian + ("IIIIIIII" if bits == 1 else "IIQQQQQQ"), program_headers, index * entry_size)
            kind, segment_offset, length = (ph[0], ph[1], ph[4]) if bits == 1 else (ph[0], ph[2], ph[5])
            if segment_offset + length > info.st_size:
                raise ContractError("ELF segment is outside the file")
            if kind == 3:
                if interpreter is not None or length < 2 or length > 512:
                    raise ContractError("Invalid or duplicate ELF interpreter")
                stream.seek(segment_offset)
                raw = stream.read(length)
                if len(raw) != length or not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                    raise ContractError("Invalid ELF interpreter string")
                try:
                    interpreter = raw[:-1].decode("ascii")
                except UnicodeError:
                    raise ContractError("Unsupported ELF interpreter encoding") from None
        # ET_DYN alone also describes a shared library or static PIE. Even an
        # interpreter-bearing ET_DYN is only a binary-layout candidate here.
        layout = "fixed_address_executable_candidate" if file_type == 2 else "dynamic_executable_candidate" if file_type == 3 and interpreter else "shared_or_static_pie_unknown" if file_type == 3 else "unknown"
        basename = (interpreter or "").rsplit("/", 1)[-1]
        libc = "musl_loader_candidate" if basename.startswith("ld-musl-") else "glibc_loader_candidate" if basename.startswith("ld-linux") else "unknown"
        return {"class": 32 if bits == 1 else 64, "layout": layout, "libc": libc}


def elf_result(path, root, asset_id):
    relative = adapter_path(path, root)
    observed = inspect_elf(path)
    detail = (f"ELF{observed['class']} metadata: layout={observed['layout']}; libc={observed['libc']}. "
              "The file is not verified as the deployed Node executable; interpreter naming is a hint, not loaded-libc evidence. "
              "PIE/libc/runtime mitigation remain unknown. No binary was executed or mapped.")
    return adapter_result(asset_id, "ELF metadata (runtime identity unverified)",
                          [{"id": "elf-layout", "kind": "inventory", "state": "candidate", "detail": detail, "path": relative}])


def _metadata_version_result(component, version, relative, asset_id, *, uncertain=False):
    if version is not None and not isinstance(version, str):
        raise ContractError("Metadata version must be text or missing")
    exact = exact_version(version) if isinstance(version, str) else None
    value = version if exact and not uncertain else None
    detail = component + " metadata version: " + (value or "missing, qualified, linked or conflicting") + ". Library linkage and build provenance remain unknown; this is not a patch verdict."
    return adapter_result(asset_id, component + " package metadata", [{"id": "metadata-version", "kind": "inventory",
                          "state": "present" if value else "unknown", "detail": detail, "path": relative}], version=value)


def metadata_results(path, root, mode, prefix):
    relative = adapter_path(path, root)
    data = load_json(path)
    if not isinstance(data, dict):
        raise ContractError("Metadata must be an object")
    selected = []
    if mode == "npm":
        lv = data.get("lockfileVersion")
        if type(lv) is not int or lv not in {1, 2, 3}:
            raise ContractError("Unsupported npm lock version")
        if lv in {2, 3}:
            packages = data.get("packages")
            if not isinstance(packages, dict) or len(packages) > 10000:
                raise ContractError("Invalid or excessive npm packages")
            for location, item in packages.items():
                if not isinstance(item, dict) or not isinstance(location, str) or len(location) > 512:
                    raise ContractError("Invalid npm package metadata")
                if "link" in item and type(item["link"]) is not bool:
                    raise ContractError("Invalid npm link flag")
                canonical = location == "node_modules/sharp" or location.endswith("/node_modules/sharp")
                if canonical or item.get("name") == "sharp":
                    selected.append(("Sharp", item.get("version"), bool(item.get("link")) or (canonical and item.get("name", "sharp") != "sharp")))
        if lv == 1 or "dependencies" in data:
            pending = [(data.get("dependencies", {}), 0)]
            count = 0
            while pending:
                dependencies, depth = pending.pop()
                if not isinstance(dependencies, dict) or depth > 30:
                    raise ContractError("Invalid dependency tree")
                for name, item in dependencies.items():
                    count += 1
                    if count > 10000 or not isinstance(item, dict):
                        raise ContractError("Invalid or excessive dependencies")
                    if "link" in item and type(item["link"]) is not bool:
                        raise ContractError("Invalid npm link flag")
                    if name == "sharp" or item.get("name") == "sharp":
                        selected.append(("Sharp", item.get("version"), bool(item.get("link")) or lv != 1))
                    if "dependencies" in item:
                        pending.append((item["dependencies"], depth + 1))
    elif data.get("bomFormat") == "CycloneDX" and isinstance(data.get("specVersion"), str) and data["specVersion"] in {"1.4", "1.5", "1.6"}:
        pending = [data.get("components", [])]
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ContractError("Invalid SBOM metadata")
        if "component" in metadata:
            if not isinstance(metadata["component"], dict):
                raise ContractError("Invalid SBOM subject component")
            pending.append([metadata["component"]])
        count = 0
        while pending:
            components = pending.pop()
            if not isinstance(components, list):
                raise ContractError("Invalid SBOM component list")
            for item in components:
                count += 1
                if count > 10000 or not isinstance(item, dict):
                    raise ContractError("Invalid or excessive SBOM components")
                if "name" in item and not isinstance(item["name"], str):
                    raise ContractError("SBOM component name must be text")
                if item.get("name") in {"sharp", "librsvg"}:
                    selected.append(("Sharp" if item["name"] == "sharp" else "librsvg", item.get("version"), False))
                if "components" in item:
                    pending.append(item["components"])
    elif isinstance(data.get("spdxVersion"), str) and data["spdxVersion"] in {"SPDX-2.2", "SPDX-2.3"}:
        packages = data.get("packages", [])
        if not isinstance(packages, list) or len(packages) > 10000:
            raise ContractError("Invalid or excessive SPDX packages")
        for item in packages:
            if not isinstance(item, dict):
                raise ContractError("Invalid SPDX package")
            if "name" in item and not isinstance(item["name"], str):
                raise ContractError("SPDX package name must be text")
            if item.get("name") in {"sharp", "librsvg"}:
                selected.append(("Sharp" if item["name"] == "sharp" else "librsvg", item.get("versionInfo"), False))
    else:
        raise ContractError("Unsupported SBOM format/version")
    if len(selected) > MAX_RECORDS:
        raise ContractError("Too many selected metadata records")
    if not selected:
        return [adapter_result(prefix + "-coverage", "Package metadata coverage", [{"id": "coverage", "kind": "inventory", "state": "unknown",
                               "path": relative, "detail": "No supported Sharp/librsvg metadata observation found; absence and deployed selection are not established."}])]
    return [_metadata_version_result(component, version, relative, prefix + "-" + str(index + 1), uncertain=uncertain)
            for index, (component, version, uncertain) in enumerate(selected)]


# Lexer bundled from vm2-nesting-check 1cd5347, under the same licensing.
def _js_tokens(text):
    """Bounded lexical hints, not a JavaScript parser. Never retain source strings."""
    tokens = []
    index, line = 0, 1
    while index < len(text):
        start = index
        char = text[index]
        if char.isspace():
            line += char == "\n"
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("Unterminated JavaScript comment")
            line += text.count("\n", index, end + 2)
            index = end + 2
            continue
        token_line = line
        if char in "\"'`":
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == char:
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise ValueError("Unterminated JavaScript string or template")
            raw = text[start + 1:index - 1]
            value = "@template" if char == "`" else "@" + raw if raw in {"sharp", "VipsForeignLoadSvg", "operation"} else "@string"
            line += text.count("\n", start, index)
        elif char == "/" and (not tokens or tokens[-1][0] in {"=", "(", "[", "{", ":", ",", ";", "return", "=>"}):
            # Regex bodies are opaque. Templates (including interpolations) are
            # also opaque; the report always states incomplete lexical coverage.
            index += 1
            in_class = False
            while index < len(text):
                c = text[index]
                if c == "\\":
                    index += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    index += 1
                    break
                elif c == "\n":
                    raise ValueError("Unterminated JavaScript regex candidate")
                index += 1
            else:
                raise ValueError("Unterminated JavaScript regex candidate")
            value = "@regex"
        elif char.isascii() and (char.isalpha() or char in "_$"):
            index += 1
            while index < len(text) and text[index].isascii() and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            value = text[start:index]
        elif text.startswith("...", index):
            value, index = "...", index + 3
        else:
            value, index = char, index + 1
        tokens.append((value, token_line))
        if len(tokens) > 200000:
            raise ValueError("Source exceeds the 200,000 token limit")
    return tokens


def source_results(path, root, prefix):
    relative = adapter_path(path, root)
    text = _read_regular_file(path, MAX_JSON_BYTES).decode("utf-8-sig")
    tokens = _js_tokens(text)
    values = [token[0] for token in tokens]
    bindings = set()
    ident = r"[A-Za-z_$][A-Za-z0-9_$]*"
    for index, value in enumerate(values):
        if value not in {"import", "const", "let", "var"}:
            continue
        statement = " ".join(values[index:index + 20])
        match = re.match(r"import (" + ident + r") from @sharp(?: |$)", statement)
        if not match:
            match = re.match(r"(?:const|let|var) (" + ident + r") = require \( @sharp \)", statement)
        if match:
            bindings.add(match[1])
    evidence = []
    for index, value in enumerate(values[:-1]):
        if value not in bindings:
            continue
        operation, detail = None, ""
        if values[index + 1] == "(":
            operation = "decode-input"
            detail = "Import-associated Sharp factory call candidate. Input format, attacker control and deployed execution remain unknown."
        elif (index + 3 < len(values) and values[index + 1] == "." and values[index + 2] in {"block", "unblock"}
              and values[index + 3] == "("):
            operation = values[index + 2]
            # A small local window is a search hint, never effective mitigation.
            marker = "present_in_window" if "@VipsForeignLoadSvg" in values[index + 4:index + 68] else "not_observed_in_window"
            detail = f"Sharp {operation} call candidate; SVG loader marker {marker}. The bounded window may include unrelated code. Ordering, branches, dynamic configuration and deployment are unresolved; no effective mitigation is inferred."
        if operation:
            evidence.append({"id": "source-" + str(len(evidence) + 1), "kind": "source", "state": "candidate",
                             "path": relative, "line": tokens[index][1], "detail": detail + " Aliases, shadowing, reassignment, templates, regex/division and unsupported syntax require manual review."})
            if len(evidence) > 100:
                raise ContractError("Too many source candidates in one file")
    if not evidence:
        evidence.append({"id": "coverage", "kind": "source", "state": "unknown", "path": relative,
                         "detail": "No supported import-associated Sharp call candidate found. Coverage is limited lexical; absence, input trust and runtime mitigation are not established."})
    return [adapter_result(prefix, "Sharp source candidates", evidence)]


