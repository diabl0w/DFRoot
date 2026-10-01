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
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
EXP = (ROOT / "app/src/main/jni/exp.c").read_text()
JAVA = (ROOT / "app/src/main/java/df/root/ExploitRunner.java").read_text()
LIBCXX = (ROOT / "app/src/main/jni/libcxx.S").read_text()
GRADLE = (ROOT / "app/build.gradle.kts").read_text()


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
        if content.returncode:
            detail = (content.stderr or content.stdout).decode(errors="replace").strip()
            result["content_status"] = error_status(detail)
            result["content_error"] = detail
        else:
            result["content_status"] = "readable"
            result["content_size"] = len(content.stdout)
            result["sha256"] = hashlib.sha256(content.stdout).hexdigest()
    return result


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
    serial: str, minimum_size: int, expected_label: str, limit: int = 64
) -> dict[str, object]:
    """Summarize a bounded, shell-visible /vendor/lib64 scan.

    This deliberately does not call the results usable. Android SELinux may
    hide other paths from ADB shell, and the loader domain still has to be
    checked against the device policy.
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
    paths = [line for line in found.splitlines() if line.startswith("/vendor/lib64/")]
    paths = paths[:limit]
    if not paths:
        return {
            "status": "no_shell_visible_files",
            "paths_seen": 0,
            "complete": False,
        }

    listing = adb_result(serial, "shell", "ls", "-ldZ", *paths)
    lines = listing.stdout.decode(errors="replace").splitlines()
    contexts: dict[str, list[dict[str, object]]] = defaultdict(list)
    eligible = []
    for line in lines:
        metadata = parse_ls_line(line)
        label = metadata.get("selinux_label")
        size = metadata.get("lstat_size")
        if not isinstance(label, str) or not isinstance(size, int) or size < minimum_size:
            continue
        path = line.split()[-1]
        item = {"path": path, "size": size, "selinux_label": label}
        contexts[label].append(item)
        if label == expected_label:
            eligible.append(item)

    context_summary = []
    for label, items in sorted(contexts.items()):
        context_summary.append({
            "selinux_label": label,
            "count": len(items),
            "examples": items[:3],
        })
    return {
        "status": "bounded_shell_scan",
        "root": "/vendor/lib64",
        "paths_seen": len(paths),
        "policy_hidden_entries": len(denied_lines),
        "scan_limit": limit,
        "minimum_size": minimum_size,
        "expected_loader_label": expected_label,
        "expected_label_matches": eligible[:5],
        "label_summary": context_summary,
        "complete": False,
        "limitation": (
            "only top-level files visible to the ADB shell are included; policy-hidden "
            "files and other vendor directories require a validated privileged read bridge"
        ),
    }


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", help="ADB device serial")
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

    carrier_paths = sorted(set(re.findall(r'"(/vendor/lib64/[^"\n]+\.so)"', JAVA)))
    carriers = [path_metadata(serial, path, fingerprint=True) for path in carrier_paths]
    expected_carrier_label = "u:object_r:vendor_file:s0"
    carrier_scan = scan_visible_carriers(
        serial,
        int(selected_module["padded_size"]) if selected_module else maximum_bundled_module_size,
        expected_carrier_label,
    )

    config = None
    try:
        config = gzip.decompress(
            adb(serial, "exec-out", "cat", "/proc/config.gz", binary=True)
        ).decode(errors="replace")
    except (RuntimeError, OSError, gzip.BadGzipFile):
        pass
    option_names = (
        "XFRM", "INET_ESP", "MODULES", "MODVERSIONS", "MODULE_SIG",
        "MODULE_SIG_FORCE", "CFI_CLANG", "KALLSYMS",
    )
    options = (
        {name: config_value(config, name) for name in option_names}
        if config is not None else None
    )

    modules_disabled_probe = adb_result(
        serial, "shell", "cat", "/proc/sys/kernel/modules_disabled"
    )
    if modules_disabled_probe.returncode:
        detail = (modules_disabled_probe.stderr or modules_disabled_probe.stdout).decode(
            errors="replace"
        ).strip()
        modules_disabled = {
            "value": None,
            "status": error_status(detail),
            "probe_error": detail,
        }
    else:
        raw_value = modules_disabled_probe.stdout.decode(errors="replace").strip()
        try:
            value = int(raw_value)
        except ValueError:
            value = None
        modules_disabled = {"value": value, "status": "readable", "raw": raw_value}

    blockers: list[str] = []
    unknowns: list[str] = []
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
    if not any(item["present"] is True for item in carriers):
        if any(item["present"] is None for item in carriers):
            unknowns.append("supported carrier paths are hidden from the ADB shell")
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
            module_signature_policy = "not forced by config"
            unknowns.append(
                "modified-module acceptance still needs an exact-firmware finit_module test"
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
    if options is not None and options["XFRM"] == "y" and options["INET_ESP"] in ("y", "m"):
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
    if not any(item["present"] is True for item in carriers):
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
                "configured carriers are not confirmed visible to the ADB shell",
                f"expected loader-compatible label={expected_carrier_label}",
                f"shell-visible carrier labels={visible_labels or 'none'}",
                f"shell-visible expected-label matches={len(expected_label_matches)}",
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
        "serial": serial,
        "device": {
            "fingerprint": fingerprint,
            "build_incremental": incremental,
            "android": release,
            "api": sdk,
            "kernel_release": kernel,
            "kernel_version": kernel_version,
            "adb_identity": identity,
            "selinux": selinux,
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
        "carrier_candidates": carriers,
        "carrier_visibility_scan": carrier_scan,
        "kernel_options": options,
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
        "blockers": blockers,
        "unknowns": unknowns,
        "assessment": assessment,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
