#!/usr/bin/env python3
"""Read-only DFRoot compatibility report for an ADB-attached Android device.

The report checks packaged-payload prerequisites and emits evidence-backed
next steps. It does not test the DirtyFrag primitive, load a module, or change
the device.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
EXP = (ROOT / "app/src/main/jni/exp.c").read_text()
JAVA = (ROOT / "app/src/main/java/df/root/ExploitRunner.java").read_text()
LIBCXX = (ROOT / "app/src/main/jni/libcxx.S").read_text()
GRADLE = (ROOT / "app/build.gradle.kts").read_text()

SYMBOL_TARGETS = (
    "_text",
    "_stext",
    "kallsyms_lookup_name",
    "selinux_state",
    "selinux_enforcing",
    "enforcing_enabled",
    "security_hook_heads",
    "sysctl_perf_event_paranoid",
    "kptr_restrict",
    "sig_enforce",
    "modules_disabled",
    "load_module",
    "mod_verify_sig",
    "register_kprobe",
    "unregister_kprobe",
    "call_usermodehelper_setup",
    "call_usermodehelper_exec",
)

CONFIG_OPTIONS = (
    "XFRM",
    "INET_ESP",
    "MODULES",
    "MODULE_UNLOAD",
    "MODVERSIONS",
    "MODULE_SIG",
    "MODULE_SIG_FORCE",
    "MODULE_SIG_ALL",
    "CFI_CLANG",
    "LTO_CLANG",
    "KALLSYMS",
    "KALLSYMS_ALL",
    "KALLSYMS_BASE_RELATIVE",
    "RELOCATABLE",
    "RANDOMIZE_BASE",
    "IKCONFIG",
    "IKCONFIG_PROC",
    "SECURITY_SELINUX",
    "SECURITY_SELINUX_DEVELOP",
    "PERF_EVENTS",
    "HW_PERF_EVENTS",
)

FRESH_PROCESS_CARRIERS = (
    {
        "name": "adbd",
        "path": "/system/bin/adbd",
        "fresh_trigger": "controlled daemon restart with a pre-recorded fallback transport",
        "use": "verify daemon UID, capabilities, child shell domain, and restoration separately",
    },
    {
        "name": "dumpstate",
        "path": "/system/bin/dumpstate",
        "fresh_trigger": "one bounded bugreport request",
        "use": "probe a fresh diagnostic domain and return evidence through shell-writable storage",
    },
    {
        "name": "crash_dump64",
        "path": "/system/bin/crash_dump64",
        "fresh_trigger": "one controlled disposable-process crash",
        "use": "validate a transient protected-file read bridge before any privileged payload",
    },
)


def adb_result(serial: str, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["adb", "-s", serial, *args],
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def adb(serial: str, *args: str, binary: bool = False):
    result = adb_result(serial, *args)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors="replace").strip()
        raise RuntimeError(detail or f"adb exited {result.returncode}")
    return result.stdout if binary else result.stdout.decode(errors="replace").strip()


def shell(serial: str, *args: str) -> str:
    return adb(serial, "shell", *args)


def error_status(detail: str) -> str:
    lowered = detail.lower()
    if "permission denied" in lowered or "inaccessible" in lowered:
        return "permission_denied"
    if "no such file" in lowered or "not found" in lowered:
        return "absent"
    return "probe_failed"


def cat_diagnostic(path: str, stdout: bytes, stderr: bytes) -> str | None:
    """Return a Toybox cat diagnostic even when adb incorrectly reports success.

    Some Android builds return status 0 from ``adb exec-out cat`` while Toybox
    writes a failed open diagnostic to stdout.  Only classify the exact
    one-line diagnostic form for the requested path, so ordinary file content
    that happens to contain the word ``cat`` is left alone.
    """
    candidates = []
    for stream in (stderr, stdout):
        text = stream.decode(errors="replace").strip()
        if text:
            candidates.append(text)
    escaped_path = re.escape(path)
    pattern = re.compile(
        rf"^(?:cat:\s*)?{escaped_path}:\s*"
        r"(?:Permission denied|No such file or directory|Not a directory|"
        r"Operation not permitted|Is a directory)$",
        re.IGNORECASE,
    )
    return next((detail for detail in candidates if pattern.fullmatch(detail)), None)


def cat_result_error(path: str, result: subprocess.CompletedProcess) -> str | None:
    diagnostic = cat_diagnostic(path, result.stdout, result.stderr)
    if diagnostic is not None:
        return diagnostic
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors="replace").strip()
        return detail or f"cat exited {result.returncode}"
    return None


def parse_ls_line(line: str) -> dict[str, object]:
    result: dict[str, object] = {"ls": line}
    parts = line.split()
    if parts:
        result["mode"] = parts[0]
    for index, part in enumerate(parts):
        if part.startswith("u:object_r:"):
            result["selinux_label"] = part
            if index + 1 < len(parts) and parts[index + 1].isdigit():
                result["lstat_size"] = int(parts[index + 1])
            break
    link_match = re.search(r" -> (.+)$", line)
    if link_match:
        result["link_target"] = link_match.group(1)
    return result


def path_metadata(serial: str, path: str, fingerprint: bool = False) -> dict[str, object]:
    result: dict[str, object] = {"path": path}
    probe = adb_result(serial, "shell", "ls", "-ldZ", path)
    stdout = probe.stdout.decode(errors="replace").strip()
    stderr = probe.stderr.decode(errors="replace").strip()
    detail = stderr or stdout
    if probe.returncode:
        status = error_status(detail)
        result["status"] = status
        result["present"] = False if status == "absent" else None
        result["probe_error"] = detail
        return result

    result.update(parse_ls_line(stdout))
    result["status"] = "visible"
    result["present"] = True
    link_target = result.get("link_target")
    if isinstance(link_target, str):
        resolved_target = str(PurePosixPath(path).parent / link_target)
        target_probe = adb_result(serial, "shell", "ls", "-ldZ", resolved_target)
        target_stdout = target_probe.stdout.decode(errors="replace").strip()
        target_stderr = target_probe.stderr.decode(errors="replace").strip()
        if target_probe.returncode:
            detail = target_stderr or target_stdout
            status = error_status(detail)
            result["link_target_probe"] = {
                "path": resolved_target,
                "status": status,
                "present": False if status == "absent" else None,
                "probe_error": detail,
            }
        else:
            result["link_target_probe"] = {
                "path": resolved_target,
                "status": "visible",
                "present": True,
                **parse_ls_line(target_stdout),
            }
    if fingerprint:
        content = adb_result(serial, "exec-out", "cat", path)
        detail = cat_result_error(path, content)
        if detail is not None:
            result["content_status"] = error_status(detail)
            result["content_error"] = detail
        else:
            result["content_status"] = "readable"
            result["content_size"] = len(content.stdout)
            result["sha256"] = hashlib.sha256(content.stdout).hexdigest()
    return result


def remote_file(serial: str, path: str) -> tuple[dict[str, object], bytes | None]:
    """Read a device file without treating policy denial as absence."""
    result = adb_result(serial, "exec-out", "cat", path, timeout=60)
    detail = cat_result_error(path, result)
    if detail is not None:
        return ({
            "path": path,
            "status": error_status(detail),
            "probe_error": detail,
        }, None)
    raw = result.stdout
    return ({
        "path": path,
        "status": "readable",
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }, raw)


def scalar_probe(serial: str, path: str) -> dict[str, object]:
    metadata, raw = remote_file(serial, path)
    if raw is None:
        metadata["value"] = None
        return metadata
    value = raw.decode(errors="replace").strip()
    metadata["value"] = value
    return metadata


def app_private_json(
    serial: str, package: str, relative_path: str
) -> dict[str, object]:
    result = adb_result(
        serial, "exec-out", "run-as", package, "cat", relative_path, timeout=30
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors="replace").strip()
        lowered = detail.lower()
        status = (
            "not_available"
            if "unknown package" in lowered
            or "package not debuggable" in lowered
            or "no such file" in lowered
            else error_status(detail)
        )
        return {
            "status": status,
            "package": package,
            "relative_path": relative_path,
            "probe_error": detail or f"run-as cat exited {result.returncode}",
        }
    raw = result.stdout
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "status": "invalid_json",
            "package": package,
            "relative_path": relative_path,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "decode_error": str(exc),
        }
    return {
        "status": "readable",
        "package": package,
        "relative_path": relative_path,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "result": parsed,
    }


def parse_symbol_table(text: str) -> list[dict[str, object]]:
    symbols: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+([A-Za-z?])\s+(\S+)", line)
        if not match:
            continue
        symbols.append({
            "address": int(match.group(1), 16),
            "type": match.group(2),
            "name": match.group(3),
            "line": line_number,
        })
    return symbols


def summarize_symbols(
    symbols: list[dict[str, object]], source: str
) -> dict[str, object]:
    nonzero = [item for item in symbols if int(item["address"]) != 0]
    by_name: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in symbols:
        if str(item["name"]) in SYMBOL_TARGETS:
            by_name[str(item["name"])].append(item)

    base_item = next(
        (
            item
            for base_name in ("_text", "_stext")
            for item in by_name.get(base_name, [])
            if int(item["address"]) != 0
        ),
        None,
    )
    base_address = int(base_item["address"]) if base_item is not None else None
    selected: dict[str, list[dict[str, object]]] = {}
    for name in SYMBOL_TARGETS:
        matches = []
        for item in by_name.get(name, []):
            address = int(item["address"])
            entry: dict[str, object] = {
                "address": f"0x{address:x}",
                "type": item["type"],
                "source_line": item["line"],
            }
            if base_address is not None and address != 0:
                entry["text_relative_offset"] = f"0x{address - base_address:x}"
            matches.append(entry)
        selected[name] = matches

    if not symbols:
        address_state = "no_parseable_symbols"
    elif not nonzero:
        address_state = "all_addresses_zero_or_redacted"
    elif base_address is None:
        address_state = "nonzero_addresses_without_text_base"
    else:
        address_state = "nonzero_addresses_with_text_base"
    return {
        "source": source,
        "parsed_symbol_count": len(symbols),
        "nonzero_address_count": len(nonzero),
        "address_state": address_state,
        "base_symbol": str(base_item["name"]) if base_item is not None else None,
        "base_address": f"0x{base_address:x}" if base_address is not None else None,
        "targets": selected,
    }


def symbol_probe(
    serial: str,
    symbol_map: Path | None,
    kernel_image: Path | None,
) -> dict[str, object]:
    live_metadata, live_raw = remote_file(serial, "/proc/kallsyms")
    if live_raw is None:
        live = {**live_metadata, "address_state": "unavailable"}
    else:
        live = {
            **live_metadata,
            **summarize_symbols(
                parse_symbol_table(live_raw.decode(errors="replace")),
                "/proc/kallsyms",
            ),
        }

    offline: dict[str, object]
    offline_summary: dict[str, object] | None = None
    if symbol_map is None:
        offline = {
            "status": "not_supplied",
            "required_input": "--symbol-map PATH",
        }
    else:
        raw = symbol_map.read_bytes()
        offline_summary = summarize_symbols(
            parse_symbol_table(raw.decode(errors="replace")), str(symbol_map)
        )
        offline = {
            "status": "readable",
            "path": str(symbol_map.resolve()),
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            **offline_summary,
        }

    image: dict[str, object]
    if kernel_image is None:
        image = {
            "status": "not_supplied",
            "required_input": "--kernel-image PATH",
        }
    else:
        raw_image = kernel_image.read_bytes()
        image = {
            "status": "readable",
            "path": str(kernel_image.resolve()),
            "size": len(raw_image),
            "sha256": hashlib.sha256(raw_image).hexdigest(),
            "mapping_assumption": (
                "raw uncompressed kernel Image file offset 0 corresponds to _text; "
                "verify this independently before using any byte window"
            ),
        }
        windows: dict[str, list[dict[str, object]]] = {}
        if offline_summary is not None:
            for name, matches in offline_summary["targets"].items():
                target_windows = []
                for match in matches:
                    offset_text = match.get("text_relative_offset")
                    if not isinstance(offset_text, str):
                        continue
                    offset = int(offset_text, 16)
                    start = max(0, offset - 16)
                    end = min(len(raw_image), offset + 32)
                    if offset < 0 or offset >= len(raw_image):
                        target_windows.append({
                            "text_relative_offset": offset_text,
                            "status": "outside_image",
                        })
                        continue
                    target_windows.append({
                        "text_relative_offset": offset_text,
                        "assumed_file_offset": f"0x{offset:x}",
                        "window_start": f"0x{start:x}",
                        "symbol_index_in_window": offset - start,
                        "bytes_hex": raw_image[start:end].hex(),
                        "status": "bytes_recorded_under_unverified_mapping_assumption",
                    })
                windows[name] = target_windows
        image["target_byte_windows"] = windows

    if live.get("address_state") == "nonzero_addresses_with_text_base":
        offset_basis = "live_kallsyms"
    elif offline.get("address_state") == "nonzero_addresses_with_text_base":
        offset_basis = "offline_symbol_map"
    else:
        offset_basis = "none"
    return {
        "targets": list(SYMBOL_TARGETS),
        "live": live,
        "offline": offline,
        "kernel_image": image,
        "offset_basis": offset_basis,
        "live_base_status": (
            "observed" if offset_basis == "live_kallsyms" else "not_observed"
        ),
        "interpretation": (
            "An offline text-relative offset is not a live address. If KASLR or relocation "
            "is enabled, derive the live base independently. Byte windows are evidence only "
            "when the exact image hash and file-offset mapping are both verified."
        ),
    }


def selinux_policy_probe(serial: str) -> dict[str, object]:
    path = "/vendor/etc/selinux/vendor_sepolicy.cil"
    metadata, raw = remote_file(serial, path)
    if raw is None:
        return metadata
    text = raw.decode(errors="replace")
    module_rules = re.findall(
        r"^\(allow\s+vendor_modprobe\s+(\S+)\s+\(system\s+\(module_load\)\)\)",
        text,
        re.M,
    )
    read_rules = re.findall(
        r"^\(allow\s+vendor_modprobe\s+(\S+)\s+\(file\s+\(([^)]*)\)\)\)",
        text,
        re.M,
    )

    def normalize_type(value: str) -> str:
        return re.sub(r"_\d+_\d+$", "", value)

    return {
        **metadata,
        "vendor_modprobe_module_load_types_raw": module_rules,
        "vendor_modprobe_module_load_types": sorted({normalize_type(x) for x in module_rules}),
        "vendor_modprobe_file_rules": [
            {"type_raw": name, "type": normalize_type(name), "permissions": perms.split()}
            for name, perms in read_rules
        ],
        "interpretation": (
            "A visible file is only a loader carrier candidate when its runtime SELinux type "
            "is permitted by the actual loader domain for both file access and module_load."
        ),
    }


def module_state_probe(serial: str) -> dict[str, object]:
    metadata, raw = remote_file(serial, "/proc/modules")
    if raw is None:
        return metadata
    modules = []
    for line in raw.decode(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        modules.append({
            "name": parts[0],
            "size": int(parts[1]) if parts[1].isdigit() else parts[1],
            "state": parts[4],
            "address": parts[5],
            "taint": parts[6] if len(parts) > 6 else None,
        })
    addresses = [str(item["address"]) for item in modules]
    return {
        **metadata,
        "loaded_module_count": len(modules),
        "loaded_modules": modules,
        "address_state": (
            "all_zero_or_redacted"
            if modules and all(int(value, 16) == 0 for value in addresses)
            else "contains_nonzero_addresses"
            if modules
            else "no_modules_listed"
        ),
    }


def config_value(config: str, key: str) -> str:
    match = re.search(rf"^CONFIG_{re.escape(key)}=(.+)$", config, re.M)
    return match.group(1) if match else "n"


def source_path(pattern: str, text: str, description: str) -> str:
    match = re.search(pattern, text)
    if not match:
        raise ValueError(f"cannot locate {description} in source")
    return match.group(1)


def bundled_modules() -> list[dict[str, object]]:
    modules = []
    for module_path in sorted((ROOT / "app/src/main/jni/ko").glob("dirtyfrag-*.ko")):
        raw = module_path.read_bytes()
        modules.append({
            "kmi": module_path.stem.removeprefix("dirtyfrag-"),
            "size": len(raw),
            "padded_size": (len(raw) + 15) & ~15,
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return sorted(modules, key=lambda item: str(item["kmi"]))


def scan_visible_carriers(
    serial: str, minimum_size: int, expected_labels: set[str], limit: int = 1024
) -> dict[str, object]:
    """Summarize a bounded, shell-visible /vendor/lib64 scan.

    Paths are sorted before truncation and metadata is queried in chunks. The
    report distinguishes all discovered paths from the subset actually
    inspected, because an early filesystem-order sample is not representative.
    """
    found_probe = adb_result(
        serial, "shell", "find", "/vendor/lib64", "-maxdepth", "1", "-type", "f"
    )
    found = found_probe.stdout.decode(errors="replace").strip()
    denied_lines = [
        line for line in found_probe.stderr.decode(errors="replace").splitlines()
        if "permission denied" in line.lower()
    ]
    if found_probe.returncode and not found:
        return {
            "status": "probe_failed",
            "probe_error": (
                found_probe.stderr.decode(errors="replace").strip()
                or f"find exited {found_probe.returncode}"
            ),
            "complete": False,
        }
    all_paths = sorted({
        line for line in found.splitlines() if line.startswith("/vendor/lib64/")
    })
    paths = all_paths[:limit]
    if not all_paths:
        return {
            "status": "no_shell_visible_files",
            "paths_discovered": 0,
            "paths_inspected": 0,
            "complete": False,
        }

    lines: list[str] = []
    listing_errors: list[str] = []
    for start in range(0, len(paths), 64):
        listing = adb_result(serial, "shell", "ls", "-ldZ", *paths[start:start + 64])
        lines.extend(listing.stdout.decode(errors="replace").splitlines())
        listing_errors.extend(
            line for line in listing.stderr.decode(errors="replace").splitlines() if line
        )
    contexts: dict[str, list[dict[str, object]]] = defaultdict(list)
    eligible: list[dict[str, object]] = []
    large_enough_count = 0
    for line in lines:
        metadata = parse_ls_line(line)
        label = metadata.get("selinux_label")
        size = metadata.get("lstat_size")
        if not isinstance(label, str) or not isinstance(size, int):
            continue
        path = line.split()[-1]
        item = {"path": path, "size": size, "selinux_label": label}
        contexts[label].append(item)
        if size < minimum_size:
            continue
        large_enough_count += 1
        if label in expected_labels:
            eligible.append(item)

    context_summary = []
    for label, items in sorted(contexts.items()):
        context_summary.append({
            "selinux_label": label,
            "count": len(items),
            "large_enough_count": sum(
                1 for item in items if int(item["size"]) >= minimum_size
            ),
            "examples": sorted(items, key=lambda item: int(item["size"]), reverse=True)[:3],
        })
    complete = len(all_paths) <= limit and not denied_lines and not listing_errors
    return {
        "status": "complete_shell_visible_scan" if complete else "bounded_shell_scan",
        "root": "/vendor/lib64",
        "paths_discovered": len(all_paths),
        "paths_inspected": len(paths),
        "policy_hidden_entries": len(denied_lines),
        "metadata_errors": listing_errors[:10],
        "scan_limit": limit,
        "minimum_size": minimum_size,
        "expected_loader_labels": sorted(expected_labels),
        "large_enough_count": large_enough_count,
        "expected_label_matches": sorted(
            eligible, key=lambda item: int(item["size"]), reverse=True
        )[:10],
        "label_summary": context_summary,
        "complete": complete,
        "limitation": (
            "only top-level regular files visible to the ADB shell are included; hidden "
            "entries and other vendor directories require a validated privileged read bridge"
        ),
    }


def fresh_process_carriers(serial: str) -> list[dict[str, object]]:
    """Report standard fresh-process candidates without claiming reachability.

    A policy-hidden executable is retained as an unknown candidate. That state
    tells the next operator to use a validated protected-file read bridge and
    pin the exact hash, rather than treating the path as absent or guessing an
    offset from another build.
    """
    result = []
    for candidate in FRESH_PROCESS_CARRIERS:
        result.append({
            **candidate,
            **path_metadata(serial, str(candidate["path"]), fingerprint=True),
            "candidate_state": "metadata_only_not_executed",
        })
    return result


def next_step(
    order: int,
    step_id: str,
    scope: str,
    status: str,
    action: str,
    evidence: list[str],
) -> dict[str, object]:
    return {
        "order": order,
        "id": step_id,
        "scope": scope,
        "status": status,
        "action": action,
        "evidence": evidence,
    }


def render_text(report: dict[str, object]) -> str:
    device = report["device"]
    symbols = report["kernel_symbol_evidence"]
    scratch = report["scratch_primitive_evidence"]
    carriers = report["carrier_visibility_scan"]
    config_evidence = report["kernel_config_evidence"]
    lines = [
        "DFRoot compatibility preflight",
        f"assessment: {report['assessment']}",
        f"fingerprint: {device['fingerprint']}",
        f"Android/API: {device['android']} / {device['api']}",
        f"kernel: {device['kernel_release']}",
        f"identity: {device['adb_identity']}",
        f"SELinux: {device['selinux']}",
        "",
        "CONFIRMED WORKING OR PRESENT",
    ]
    lines.extend(f"  + {item}" for item in report["working"])
    lines.extend(("", "CONFIRMED BLOCKERS OR MISMATCHES"))
    if report["blockers"]:
        lines.extend(f"  - {item}" for item in report["blockers"])
    else:
        lines.append("  (none established by this preflight)")
    lines.extend(("", "AMBIGUOUS OR NOT YET TESTED"))
    if report["unknowns"]:
        lines.extend(f"  ? {item}" for item in report["unknowns"])
    else:
        lines.append("  (none)")

    lines.extend(("", "KERNEL ADDRESS AND BYTE EVIDENCE"))
    lines.append(
        f"  live /proc/kallsyms: {symbols['live'].get('status')} / "
        f"{symbols['live'].get('address_state')}"
    )
    lines.append(f"  offline symbol map: {symbols['offline'].get('status')}")
    lines.append(f"  exact kernel image: {symbols['kernel_image'].get('status')}")
    lines.append(f"  usable offset basis: {symbols['offset_basis']}")
    lines.append(f"  live kernel base: {symbols['live_base_status']}")
    for source_name in ("live", "offline"):
        source = symbols[source_name]
        if source.get("base_address"):
            lines.append(
                f"  {source_name} base: {source['base_symbol']}={source['base_address']}"
            )
        for name, matches in source.get("targets", {}).items():
            for match in matches:
                lines.append(
                    f"  {source_name} {name}: address={match['address']} "
                    f"offset={match.get('text_relative_offset', 'unavailable')}"
                )
    windows = symbols["kernel_image"].get("target_byte_windows", {})
    for name, entries in windows.items():
        for entry in entries:
            if "bytes_hex" in entry:
                lines.append(
                    f"  image {name}: file_offset={entry['assumed_file_offset']} "
                    f"window={entry['bytes_hex']} ({entry['status']})"
                )

    lines.extend(("", "SCRATCH PRIMITIVE EVIDENCE"))
    lines.append(f"  artifact: {scratch.get('status')}")
    scratch_result = scratch.get("result", {})
    if isinstance(scratch_result, dict) and scratch_result:
        lines.append(f"  state: {scratch_result.get('state', 'unavailable')}")
        lines.append(
            f"  result build: {scratch_result.get('build_fingerprint', 'unavailable')}"
        )
        lines.append(
            f"  result kernel: {scratch_result.get('kernel_release', 'unavailable')}"
        )
        if scratch_result.get("before"):
            lines.append(
                f"  bytes at {scratch_result.get('offset')} len={scratch_result.get('length')}: "
                f"before={scratch_result.get('before')}"
            )
            lines.append(
                "  requested/observed="
                f"{scratch_result.get('requested_and_observed')}"
            )
            lines.append(
                "  reopened after restore="
                f"{scratch_result.get('reopened_after_restore')}"
            )
        lines.append(f"  private scratch deleted: {scratch_result.get('scratch_deleted')}")

    lines.extend(("", "CARRIER EVIDENCE"))
    lines.append(
        f"  scan: {carriers.get('status')} discovered={carriers.get('paths_discovered', 0)} "
        f"inspected={carriers.get('paths_inspected', 0)} complete={carriers.get('complete')}"
    )
    lines.append(
        f"  policy-compatible visible matches: "
        f"{len(carriers.get('expected_label_matches', []))}"
    )
    for summary in carriers.get("label_summary", []):
        lines.append(
            f"  {summary['selinux_label']}: total={summary['count']} "
            f"large_enough={summary['large_enough_count']}"
        )

    lines.extend(("", "FRESH PROCESS CARRIER CANDIDATES"))
    for candidate in report["fresh_process_carriers"]:
        lines.append(
            f"  {candidate['name']}: {candidate['path']} "
            f"evidence={candidate['candidate_state']} "
            f"status={candidate.get('status')} "
            f"label={candidate.get('selinux_label', 'unavailable')} "
            f"sha256={candidate.get('sha256', 'unavailable')}"
        )
        lines.append(f"    trigger: {candidate['fresh_trigger']}")
        lines.append(f"    prove: {candidate['use']}")

    lines.extend(("", "PROFILING INTERFACE EVIDENCE"))
    profiling = report["profiling_interfaces"]
    for name in (
        "kgsl_device", "kgsl_sysfs", "kgsl_debugfs", "tracefs_events",
        "simpleperf", "perfetto",
    ):
        item = profiling[name]
        lines.append(
            f"  {name}: evidence=path_metadata_only "
            f"path={item.get('path', 'unavailable')} "
            f"status={item.get('status', 'unavailable')} "
            f"label={item.get('selinux_label', 'unavailable')} "
            f"sha256={item.get('sha256', 'unavailable')}"
        )
    lines.append(
        "  gpu_model: "
        f"status={profiling['gpu_model'].get('status', 'unavailable')} "
        f"value={profiling['gpu_model'].get('value', 'unavailable')}"
    )
    lines.append(
        "  perf_event_paranoid: "
        f"status={profiling['perf_event_paranoid'].get('status', 'unavailable')} "
        f"value={profiling['perf_event_paranoid'].get('value', 'unavailable')}"
    )

    lines.extend(("", "PINNED EVIDENCE"))
    lines.append(
        f"  /proc/config.gz: {config_evidence.get('status')} "
        f"sha256={config_evidence.get('sha256', 'unavailable')}"
    )
    for name, info in report["configured_paths"].items():
        lines.append(
            f"  {name}: {info['path']} status={info['status']} "
            f"label={info.get('selinux_label', 'unavailable')} "
            f"sha256={info.get('sha256', 'unavailable')}"
        )

    lines.extend(("", "ORDERED NEXT STEPS"))
    for step in report["next_steps"]:
        lines.append(
            f"  {step['order']}. [{step['status']}] {step['id']}: {step['action']}"
        )
        lines.extend(f"       evidence: {item}" for item in step["evidence"])
    lines.extend(("", "Machine-readable form: rerun with --format json"))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", help="ADB device serial")
    parser.add_argument(
        "--format", choices=("json", "text"), default="json",
        help="report format (default: json)",
    )
    parser.add_argument(
        "--carrier-scan-limit", type=int, default=1024,
        help="maximum shell-visible /vendor/lib64 paths to inspect (default: 1024)",
    )
    parser.add_argument(
        "--symbol-map", type=Path,
        help="optional exact-build System.map, nm, or kallsyms-style symbol file",
    )
    parser.add_argument(
        "--kernel-image", type=Path,
        help="optional exact raw uncompressed kernel Image used to record target bytes",
    )
    args = parser.parse_args()
    serial = args.serial

    sdk = int(shell(serial, "getprop", "ro.build.version.sdk"))
    release = shell(serial, "getprop", "ro.build.version.release")
    fingerprint = shell(serial, "getprop", "ro.build.fingerprint")
    incremental = shell(serial, "getprop", "ro.build.version.incremental")
    kernel = shell(serial, "uname", "-r")
    kernel_version = shell(serial, "cat", "/proc/version")
    selinux = shell(serial, "getenforce")
    identity = shell(serial, "id")
    slot_suffix = shell(serial, "getprop", "ro.boot.slot_suffix")
    verified_boot = shell(serial, "getprop", "ro.boot.verifiedbootstate")
    vbmeta_state = shell(serial, "getprop", "ro.boot.vbmeta.device_state")
    security_patch = shell(serial, "getprop", "ro.build.version.security_patch")
    vendor_security_patch = shell(serial, "getprop", "ro.vendor.build.security_patch")
    model = shell(serial, "getprop", "ro.product.model")
    device_name = shell(serial, "getprop", "ro.product.device")

    min_sdk_match = re.search(r"\bminSdk\s*=\s*(\d+)", GRADLE)
    if not min_sdk_match:
        raise ValueError("cannot locate minSdk in app/build.gradle.kts")
    min_sdk = int(min_sdk_match.group(1))

    modules = bundled_modules()
    if not modules:
        raise ValueError("no bundled kernel modules found")
    bundled_kmis = [str(item["kmi"]) for item in modules]
    maximum_bundled_module_size = max(int(item["padded_size"]) for item in modules)
    kmi_match = re.search(r"android(\d+)-(\d+)\.(\d+)", kernel)
    device_kmi = (
        f"android{kmi_match.group(1)}-{kmi_match.group(2)}.{kmi_match.group(3)}"
        if kmi_match else None
    )
    selected_module = next((item for item in modules if item["kmi"] == device_kmi), None)

    crash_dump = source_path(
        r'static const char kCrashDump\[\] = "([^"]+)"', EXP, "crash dump path"
    )
    loader = source_path(
        r'exe_path:\s*\n\s*\.asciz "([^"]+)"', LIBCXX, "module loader path"
    )
    configured_paths = {
        "crash_dump": path_metadata(serial, crash_dump, fingerprint=True),
        "module_loader": path_metadata(serial, loader, fingerprint=False),
        "libcxx": path_metadata(serial, "/system/lib64/libc++.so", fingerprint=True),
    }

    crash_paths = list(dict.fromkeys((crash_dump, "/system/bin/crash_dump64")))
    loader_paths = list(dict.fromkeys((
        loader, "/vendor/bin/modprobe", "/system/bin/insmod", "/system/bin/modprobe"
    )))
    path_candidates = {
        "crash_dump64": [
            path_metadata(serial, path, fingerprint=True) for path in crash_paths
        ],
        "module_loader": [
            path_metadata(serial, path, fingerprint=False) for path in loader_paths
        ],
    }
    process_carriers = fresh_process_carriers(serial)

    policy = selinux_policy_probe(serial)
    allowed_carrier_types = {
        str(item) for item in policy.get("vendor_modprobe_module_load_types", [])
    }
    if not allowed_carrier_types:
        allowed_carrier_types = {"vendor_file"}
        policy["fallback_assumption"] = (
            "vendor policy could not establish loader types; vendor_file is retained only "
            "as the payload's configured expectation"
        )
    expected_carrier_labels = {
        f"u:object_r:{item}:s0" for item in allowed_carrier_types
    }

    carrier_paths = sorted(set(re.findall(r'"(/vendor/lib64/[^"\n]+\.so)"', JAVA)))
    carriers = [path_metadata(serial, path, fingerprint=True) for path in carrier_paths]
    minimum_module_size = (
        int(selected_module["padded_size"])
        if selected_module else maximum_bundled_module_size
    )
    for item in carriers:
        size = item.get("lstat_size")
        label = item.get("selinux_label")
        item["size_compatible"] = (
            isinstance(size, int) and size >= minimum_module_size
        )
        item["loader_label_compatible"] = (
            label in expected_carrier_labels if isinstance(label, str) else None
        )
        item["candidate_status"] = (
            "visible_metadata_compatible"
            if item["present"] is True
            and item["size_compatible"]
            and item["loader_label_compatible"]
            else "visible_but_incompatible"
            if item["present"] is True
            else "absent"
            if item["present"] is False
            else "unknown"
        )
    carrier_scan = scan_visible_carriers(
        serial,
        minimum_module_size,
        expected_carrier_labels,
        limit=args.carrier_scan_limit,
    )

    config_metadata, compressed_config = remote_file(serial, "/proc/config.gz")
    config = None
    if compressed_config is not None:
        try:
            config_raw = gzip.decompress(compressed_config)
            config = config_raw.decode(errors="replace")
            config_metadata["uncompressed_size"] = len(config_raw)
            config_metadata["uncompressed_sha256"] = hashlib.sha256(config_raw).hexdigest()
        except (OSError, gzip.BadGzipFile) as exc:
            config_metadata["status"] = "invalid_gzip"
            config_metadata["decode_error"] = str(exc)
    options = (
        {name: config_value(config, name) for name in CONFIG_OPTIONS}
        if config is not None else None
    )

    sysctls = {
        "modules_disabled": scalar_probe(serial, "/proc/sys/kernel/modules_disabled"),
        "kptr_restrict": scalar_probe(serial, "/proc/sys/kernel/kptr_restrict"),
        "perf_event_paranoid": scalar_probe(
            serial, "/proc/sys/kernel/perf_event_paranoid"
        ),
    }
    modules_disabled = {
        **sysctls["modules_disabled"],
        "value": (
            int(sysctls["modules_disabled"]["value"])
            if str(sysctls["modules_disabled"].get("value", "")).isdigit()
            else None
        ),
    }

    kernel_symbols = symbol_probe(serial, args.symbol_map, args.kernel_image)
    module_state = module_state_probe(serial)
    scratch_probe = app_private_json(
        serial, "df.root", "files/dirtyfrag-scratch-probe-result.json"
    )
    scratch_result = scratch_probe.get("result", {})
    scratch_current_build = (
        isinstance(scratch_result, dict)
        and scratch_result.get("build_fingerprint") == fingerprint
        and scratch_result.get("kernel_release") == kernel
    )
    scratch_confirmed = (
        scratch_probe.get("status") == "readable"
        and scratch_current_build
        and scratch_result.get("native_result") == 0
        and scratch_result.get("scratch_deleted") is True
        and scratch_result.get("state")
        == "primitive_confirmed_exact_match_restored_and_deleted"
    )
    boot_path = f"/dev/block/by-name/boot{slot_suffix}" if slot_suffix else "/dev/block/by-name/boot"
    kernel_visibility = {
        "cmdline": scalar_probe(serial, "/proc/cmdline"),
        "iomem": remote_file(serial, "/proc/iomem")[0],
        "boot_partition": path_metadata(serial, boot_path, fingerprint=False),
    }
    profiling_interfaces = {
        "kgsl_device": path_metadata(serial, "/dev/kgsl-3d0", fingerprint=False),
        "gpu_model": scalar_probe(serial, "/sys/class/kgsl/kgsl-3d0/gpu_model"),
        "kgsl_sysfs": path_metadata(
            serial, "/sys/class/kgsl/kgsl-3d0", fingerprint=False
        ),
        "kgsl_debugfs": path_metadata(serial, "/sys/kernel/debug/kgsl", fingerprint=False),
        "tracefs_events": path_metadata(
            serial, "/sys/kernel/tracing/events", fingerprint=False
        ),
        "simpleperf": path_metadata(serial, "/system/bin/simpleperf", fingerprint=True),
        "perfetto": path_metadata(serial, "/system/bin/perfetto", fingerprint=True),
        "perf_event_paranoid": sysctls["perf_event_paranoid"],
    }

    blockers: list[str] = []
    unknowns: list[str] = []
    working: list[str] = []
    if sdk < min_sdk:
        blockers.append(f"APK minSdk {min_sdk} exceeds device API {sdk}")
    if device_kmi is None:
        blockers.append(
            "kernel release has no androidNN-X.Y KMI tag; an explicit exact-firmware "
            "target and module are required"
        )
    elif selected_module is None:
        blockers.append(f"no exact bundled module for {device_kmi}")
    for name, info in configured_paths.items():
        if info["present"] is False:
            blockers.append(f"configured path absent: {name} ({info['path']})")
        elif info["present"] is None:
            unknowns.append(
                f"configured path is hidden from ADB shell: {name} ({info['path']})"
            )
    compatible_carriers = [
        item for item in carriers
        if item.get("candidate_status") == "visible_metadata_compatible"
    ]
    if not compatible_carriers:
        if any(item["present"] is None for item in carriers):
            unknowns.append(
                "one or more configured carrier paths are hidden from the ADB shell"
            )
        elif any(item["present"] is True for item in carriers):
            blockers.append(
                "configured carrier paths exist but their visible SELinux type or size is "
                "incompatible with the actual loader policy"
            )
        else:
            blockers.append("none of the supported vendor carrier paths exists")
    if modules_disabled["value"] == 1:
        blockers.append("kernel.modules_disabled is 1")
    elif modules_disabled["value"] is None:
        unknowns.append(
            f"kernel.modules_disabled is {modules_disabled['status']} from the ADB shell"
        )

    signature_forced = False
    if options is None:
        unknowns.append(
            "/proc/config.gz unavailable; kernel prerequisites and signature policy unverified"
        )
        module_signature_policy = "unknown"
    else:
        if options["XFRM"] != "y" or options["INET_ESP"] not in ("y", "m"):
            blockers.append("XFRM/INET_ESP kernel prerequisite absent")
        if options["MODULES"] != "y":
            blockers.append("loadable kernel modules are disabled in the build")
        if options["MODULE_SIG_FORCE"] == "y":
            signature_forced = True
            blockers.append(
                "kernel enforces module signatures; the modified bundled LKM cannot load"
            )
            module_signature_policy = "rejects modified or unsigned modules"
        else:
            module_signature_policy = "not forced by recovered config; dynamic result unverified"
            unknowns.append(
                "modified-module acceptance still needs an exact-firmware finit_module test"
            )

    if kernel_symbols["live"].get("status") != "readable":
        unknowns.append(
            "live kernel symbols and addresses are unavailable from the ADB shell: "
            f"{kernel_symbols['live'].get('status')}"
        )
    elif kernel_symbols["live"].get("address_state") == "all_addresses_zero_or_redacted":
        unknowns.append("live kernel symbol names are readable but addresses are zeroed")
    if kernel_symbols["offset_basis"] == "none":
        unknowns.append(
            "no exact-build symbol map was supplied, so target symbol offsets are unavailable"
        )
    if kernel_symbols["kernel_image"].get("status") != "readable":
        unknowns.append(
            "no exact raw kernel Image was supplied, so target memory bytes are unavailable"
        )
    if options is not None and options["RANDOMIZE_BASE"] == "y" \
            and kernel_symbols["live_base_status"] != "observed":
        unknowns.append(
            "CONFIG_RANDOMIZE_BASE=y and no live kernel base was observed; offline offsets "
            "must not be presented as live addresses"
        )
    if scratch_probe.get("status") == "readable" and not scratch_current_build:
        unknowns.append(
            "scratch primitive result is stale because its build fingerprint or kernel "
            "release differs from the attached device"
        )

    working.extend([
        "ADB build identity, UID/domain, and SELinux state were read",
    ])
    if config is not None:
        working.append(
            "/proc/config.gz was recovered and hashed; selected options come from this exact boot"
        )
    if options is not None and options["XFRM"] == "y" and options["INET_ESP"] in ("y", "m"):
        working.append("kernel build contains the XFRM and ESP prerequisites")
    if options is not None and options["MODULES"] == "y":
        working.append("kernel build enables loadable modules")
    if options is not None and options["MODULE_SIG_FORCE"] != "y":
        working.append("recovered config does not force module signatures")
    if module_state.get("loaded_module_count", 0):
        working.append(
            f"/proc/modules is readable and lists {module_state['loaded_module_count']} modules"
        )
    if profiling_interfaces["kgsl_device"].get("present") is True:
        working.append(
            f"KGSL device is visible as {profiling_interfaces['kgsl_device'].get('ls')}"
        )
    if profiling_interfaces["gpu_model"].get("status") == "readable":
        working.append(
            f"GPU model reports {profiling_interfaces['gpu_model'].get('value')}"
        )
    if scratch_confirmed:
        working.append(
            "scratch DirtyFrag probe produced the exact requested 16 bytes, restored the "
            "original bytes, reopened them exactly, and deleted the private file on this build"
        )

    available_crash_alternatives = [
        item for item in path_candidates["crash_dump64"]
        if item["path"] != crash_dump and item["present"] is True
    ]
    expected_label_matches = carrier_scan.get("expected_label_matches", [])
    steps: list[dict[str, object]] = []
    order = 1
    if sdk < min_sdk:
        steps.append(next_step(
            order, "build_api_compatible_apk", "userspace_stage", "required",
            (
                f"Build a separate payload variant with minSdk at or below API {sdk}; "
                "offsets and modules cannot fix APK installability."
            ),
            [f"device API={sdk}", f"current APK minSdk={min_sdk}"],
        ))
        order += 1
    if device_kmi is None or selected_module is None:
        steps.append(next_step(
            order, "add_exact_firmware_target", "userspace_and_module", "required",
            (
                "Key a new target by the full build fingerprint, kernel release, and hashes "
                "of every patched or executed file. For a non-GKI kernel, build from the "
                "exact source and config and match vermagic, CONFIG_MODVERSIONS CRCs, "
                "structure layout, and CFI behavior; do not substitute a same-version GKI module."
            ),
            [
                f"fingerprint={fingerprint}",
                f"kernel_release={kernel}",
                f"device_kmi={device_kmi}",
                f"config_sha256={config_metadata.get('sha256')}",
                f"boot_partition={boot_path}",
            ],
        ))
        order += 1
    if kernel_symbols["offset_basis"] == "none":
        steps.append(next_step(
            order, "derive_exact_symbol_offsets", "kernel_evidence", "required",
            (
                "Obtain the exact boot image without updating the device, extract the raw "
                "uncompressed kernel Image and a symbol map, then rerun this preflight with "
                "--symbol-map and --kernel-image. Record _text-relative offsets and the byte "
                "window around each target. Do not substitute symbols from another 4.19.81 build."
            ),
            [
                f"live kallsyms status={kernel_symbols['live'].get('status')}",
                f"live kallsyms address state={kernel_symbols['live'].get('address_state')}",
                f"boot node status={kernel_visibility['boot_partition'].get('status')}",
                f"boot node target={kernel_visibility['boot_partition'].get('link_target')}",
            ],
        ))
        order += 1
    if options is not None and options["RANDOMIZE_BASE"] == "y" \
            and kernel_symbols["live_base_status"] != "observed":
        steps.append(next_step(
            order, "establish_live_kernel_base", "kernel_evidence", "required_after_offsets",
            (
                "Derive the live kernel base independently before converting any offline "
                "offset into an address. Keep the offline address, text-relative offset, live "
                "base, computed live address, and bytes read back from that address as separate fields."
            ),
            [
                f"CONFIG_RELOCATABLE={options['RELOCATABLE']}",
                f"CONFIG_RANDOMIZE_BASE={options['RANDOMIZE_BASE']}",
                f"/proc/kallsyms={kernel_symbols['live'].get('status')}",
                f"/proc/iomem={kernel_visibility['iomem'].get('status')}",
            ],
        ))
        order += 1
    if configured_paths["crash_dump"]["present"] is not True and available_crash_alternatives:
        alternative = available_crash_alternatives[0]
        steps.append(next_step(
            order, "retarget_privileged_read_bridge", "userspace_stage", "candidate_found",
            (
                f"Retarget the privileged read bridge to {alternative['path']} only after "
                "pinning its SHA-256 and verifying that its SELinux label produces the "
                "required crash-dump transition. First prove harmless readback and full restoration."
            ),
            [
                f"configured path {crash_dump} is {configured_paths['crash_dump']['status']}",
                f"candidate label={alternative.get('selinux_label')}",
                f"candidate sha256={alternative.get('sha256')}",
            ],
        ))
        order += 1
    if device_kmi is None or not compatible_carriers:
        candidate_evidence = [
            f"{item['name']} path={item['path']} status={item.get('status')} "
            f"label={item.get('selinux_label', 'unavailable')} "
            f"sha256={item.get('sha256', 'unavailable')}"
            for item in process_carriers
        ]
        steps.append(next_step(
            order, "probe_fresh_privileged_process_domains", "userspace_stage",
            "alternative_before_kernel_module_work",
            (
                "If the objective can be met from a privileged userspace domain, rank fresh "
                "process carriers before pursuing a new kernel primitive. For each candidate, "
                "obtain the exact executable through a validated protected-file read bridge "
                "when shell policy hides it; pin its full hash, executable prefix, SELinux "
                "entry transition, and repeatable trigger. Run a harmless bounded payload once, "
                "restore and read back every modified byte, then record UID, capabilities, "
                "domain, and raw syscall results. Preserve a fallback transport before any "
                "daemon restart. Metadata or UID 0 alone is not success."
            ),
            candidate_evidence,
        ))
        order += 1
    if options is not None and options["XFRM"] == "y" \
            and options["INET_ESP"] in ("y", "m") and not scratch_confirmed:
        steps.append(next_step(
            order, "prove_page_cache_primitive", "userspace_stage", "unverified",
            (
                "Run a read-only or scratch-file proof for the exact firmware before "
                "patching a system or vendor file. Kernel config establishes reachability "
                "only; it does not prove the race wins or that bytes can be read or written."
            ),
            [f"CONFIG_XFRM={options['XFRM']}", f"CONFIG_INET_ESP={options['INET_ESP']}"],
        ))
        order += 1
    if signature_forced:
        steps.append(next_step(
            order, "stop_unsigned_module_chain", "module_stage", "hard_stop",
            (
                "Do not continue an unsigned or page-cache-modified module chain. Obtain a "
                "module signed by a trusted key, use an authorized offline boot image route, "
                "or first establish a separate live kernel read/write primitive. UID 0, a "
                "userspace SELinux transition, and a successful page-cache write do not "
                "bypass forced module signatures."
            ),
            [
                "CONFIG_MODULE_SIG_FORCE=y",
                "a finit_module ENOKEY result would confirm this gate dynamically",
            ],
        ))
        order += 1
        steps.append(next_step(
            order, "scope_separate_kernel_probe", "kernel_stage", "alternative",
            (
                "If pursuing a separate kernel primitive, start with a read-only exact-build "
                "probe. Extract symbols from the exact boot image, record Image-relative "
                "offsets and hashes, and obtain the live kernel base independently before "
                "interpreting any address or attempting a write."
            ),
            ["this preflight does not establish arbitrary live kernel read/write"],
        ))
        order += 1
    if not compatible_carriers:
        visible_labels = [
            str(item["selinux_label"]) for item in carrier_scan.get("label_summary", [])
        ]
        carrier_status = (
            "conditional_after_signature_gate" if signature_forced else "required"
        )
        carrier_prefix = (
            "Do not spend effort on a carrier for an unsigned module while forced "
            "signatures remain the active hard stop. If a trusted module becomes available "
            "or a safe dynamic signature-policy confirmation is still required, "
            if signature_forced else ""
        )
        steps.append(next_step(
            order, "validate_loader_carrier", "module_stage", carrier_status,
            (
                carrier_prefix
                + "enumerate a carrier large enough for the exact padded module from the "
                "privileged read context. If the visible library candidates have the wrong "
                "SELinux type, search other vendor directories from that context. Check the "
                "type against the intended loader domain before any write; path visibility "
                "and size do not prove module_load permission. Verify complete byte-for-byte "
                "readback and cleanup."
            ),
            [
                "configured carriers have no visible metadata-compatible match",
                f"loader-policy-compatible labels={sorted(expected_carrier_labels)}",
                f"shell-visible carrier labels={visible_labels or 'none'}",
                f"shell-visible expected-label matches={len(expected_label_matches)}",
                f"scan complete={carrier_scan.get('complete')}",
                f"paths discovered={carrier_scan.get('paths_discovered')}",
            ],
        ))
        order += 1
    loader_info = configured_paths["module_loader"]
    target_probe = loader_info.get("link_target_probe")
    if loader_info["present"] is True and isinstance(target_probe, dict):
        loader_status = (
            "conditional_after_signature_gate" if signature_forced else "required"
        )
        steps.append(next_step(
            order, "validate_loader_domain", "module_stage", loader_status,
            (
                "Validate the loader executable and process domain from the actual privileged "
                "execution path. A symlink can be visible while its target is hidden from the "
                "ADB shell. EPERM from a shell-domain insmod attempt establishes only a policy "
                "denial; confirm the process context and audit log before claiming that "
                "finit_module or the kernel signature verifier was reached."
            ),
            [
                f"loader path={loader_info['path']}",
                f"loader path label={loader_info.get('selinux_label')}",
                f"loader target status={target_probe.get('status')}",
            ],
        ))
        order += 1
    steps.append(next_step(
        order, "verify_outcome_boundaries", "verification", "required_after_run",
        (
            "Record UID, capabilities, SELinux domain, enforcing state, loaded-module state, "
            "and functional privilege escalation separately. A UID 0 process alone does not "
            "prove unrestricted kernel access, a loaded module, persistent root, or a "
            "signature-policy bypass."
        ),
        [f"current adb identity={identity}", f"current SELinux state={selinux}"],
    ))

    if blockers:
        assessment = "payload prerequisites unmet"
        exit_code = 2
    elif unknowns:
        assessment = "payload prerequisites inconclusive"
        exit_code = 3
    else:
        assessment = (
            "payload prerequisites present; vulnerability and module load remain untested"
        )
        exit_code = 0

    if signature_forced:
        recommended_path = "exact_firmware_userspace_stage_or_separate_kernel_primitive"
        module_chain = "hard_stop_for_modified_or_unsigned_modules"
    elif device_kmi is None or selected_module is None:
        recommended_path = "exact_firmware_port"
        module_chain = "requires_exact_module_and_dynamic_loader_test"
    else:
        recommended_path = "harmless_primitive_and_loader_validation"
        module_chain = "unverified"

    report = {
        "schema_version": 3,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_legend": {
            "confirmed": "directly read from this device or supplied exact-hash artifact",
            "blocked": "a required condition is directly absent or incompatible",
            "unknown": "the probe was denied, an exact artifact is missing, or a dynamic test remains",
            "candidate": "metadata suggests a next probe; compatibility is not yet proven",
        },
        "serial": serial,
        "device": {
            "model": model,
            "device": device_name,
            "fingerprint": fingerprint,
            "build_incremental": incremental,
            "android": release,
            "api": sdk,
            "security_patch": security_patch,
            "vendor_security_patch": vendor_security_patch,
            "kernel_release": kernel,
            "kernel_version": kernel_version,
            "adb_identity": identity,
            "selinux": selinux,
            "slot_suffix": slot_suffix,
            "verified_boot_state": verified_boot,
            "vbmeta_device_state": vbmeta_state,
        },
        "dfroot": {
            "min_api": min_sdk,
            "device_kmi": device_kmi,
            "bundled_kmis": bundled_kmis,
            "selected_module": selected_module,
            "maximum_bundled_module_padded_size": maximum_bundled_module_size,
        },
        "configured_paths": configured_paths,
        "path_candidates": path_candidates,
        "fresh_process_carriers": process_carriers,
        "carrier_candidates": carriers,
        "carrier_visibility_scan": carrier_scan,
        "selinux_loader_policy": policy,
        "kernel_config_evidence": config_metadata,
        "kernel_options": options,
        "kernel_symbol_evidence": kernel_symbols,
        "kernel_visibility": kernel_visibility,
        "module_state": module_state,
        "scratch_primitive_evidence": scratch_probe,
        "sysctls": sysctls,
        "profiling_interfaces": profiling_interfaces,
        "modules_disabled": modules_disabled,
        "module_signature_policy": module_signature_policy,
        "dynamic_module_result_hints": {
            "EPERM_with_module_load_AVC": (
                "the loader domain or carrier label is still blocked; the kernel "
                "signature verifier has not been proven reachable"
            ),
            "ENOKEY": (
                "the kernel signature verifier rejected the module; stop the modified "
                "or unsigned module chain"
            ),
            "ENOEXEC_or_invalid_module_format": (
                "recheck exact kernel build identity, vermagic, symbol CRCs, structure "
                "layout, architecture, and CFI assumptions"
            ),
            "success": (
                "verify the module in /proc/modules and test its intended function; "
                "loader exit status alone is insufficient"
            ),
        },
        "decision": {
            "recommended_path": recommended_path,
            "module_chain": module_chain,
            "automatic_path_or_carrier_substitution": "forbidden",
        },
        "next_steps": steps,
        "working": working,
        "blockers": blockers,
        "unknowns": unknowns,
        "assessment": assessment,
    }
    if args.format == "text":
        print(render_text(report))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
