#!/usr/bin/env python3
"""Read-only compatibility preflight for an ADB-attached Android device."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class PathSpec:
    name: str
    path: str
    role: str


@dataclass(frozen=True)
class PathProbe:
    name: str
    path: str
    role: str
    state: str
    mode: str | None = None
    size: int | None = None
    label: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class Finding:
    state: str
    name: str
    summary: str
    next_step: str | None = None


@dataclass
class Evidence:
    serial: str
    device: dict[str, object]
    config: dict[str, str] | None
    config_probe: dict[str, object]
    modules: dict[str, object]
    modules_disabled: dict[str, object]
    paths: list[PathProbe]
    min_api: int
    bundled_kmis: list[str]
    maximum_module_size: int


@dataclass
class Report:
    verdict: str
    evidence: Evidence
    findings: list[Finding] = field(default_factory=list)


PATHS = (
    PathSpec("crash_dump", "/apex/com.android.runtime/bin/crash_dump64", "required"),
    PathSpec("crash_dump_system", "/system/bin/crash_dump64", "alternative"),
    PathSpec("module_loader", "/vendor/bin/insmod", "required"),
    PathSpec("libcxx", "/system/lib64/libc++.so", "required"),
    PathSpec("carrier_binderdebug", "/vendor/lib64/libbinderdebug.so", "carrier"),
    PathSpec("carrier_stagefright", "/vendor/lib64/libstagefrighthw.so", "carrier"),
    PathSpec(
        "carrier_bufferpool",
        "/vendor/lib64/libstagefright_aidl_bufferpool2.so",
        "carrier",
    ),
)

CONFIG_KEYS = (
    "XFRM",
    "INET_ESP",
    "MODULES",
    "MODVERSIONS",
    "MODULE_SIG",
    "MODULE_SIG_FORCE",
    "UNMAP_KERNEL_AT_EL0",
    "RANDOMIZE_BASE",
    "STRICT_KERNEL_RWX",
    "STRICT_MODULE_RWX",
    "SECURITY_SELINUX",
    "SECURITY_SELINUX_DEVELOP",
)


class Adb:
    def __init__(self, serial: str, timeout: int = 30):
        self.serial = serial
        self.timeout = timeout

    def run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["adb", "-s", self.serial, *args],
            capture_output=True,
            check=False,
            timeout=self.timeout,
        )

    def text(self, *args: str) -> str:
        result = self.run(*args)
        if result.returncode:
            raise RuntimeError(command_error(result))
        return result.stdout.decode(errors="replace").strip()

    def property(self, name: str) -> str:
        return self.text("shell", "getprop", name)

    def read(self, path: str) -> tuple[dict[str, object], bytes | None]:
        result = self.run("exec-out", "cat", path)
        error = file_error(path, result)
        if error:
            return {"state": classify_error(error), "detail": error}, None
        raw = result.stdout
        return {
            "state": "readable",
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }, raw

    def path(self, spec: PathSpec) -> PathProbe:
        result = self.run("shell", "ls", "-ldZn", spec.path)
        text = combined_output(result)
        if result.returncode or looks_like_file_error(text):
            return PathProbe(
                spec.name,
                spec.path,
                spec.role,
                classify_error(text),
                detail=text,
            )
        return parse_path(spec, text)


def combined_output(result: subprocess.CompletedProcess[bytes]) -> str:
    streams = (result.stderr, result.stdout)
    return "\n".join(
        stream.decode(errors="replace").strip() for stream in streams if stream.strip()
    )


def command_error(result: subprocess.CompletedProcess[bytes]) -> str:
    return combined_output(result) or f"command exited {result.returncode}"


def looks_like_file_error(text: str) -> bool:
    lowered = text.lower()
    return any(
        phrase in lowered
        for phrase in (
            "permission denied",
            "operation not permitted",
            "no such file",
            "not found",
        )
    )


def file_error(
    path: str, result: subprocess.CompletedProcess[bytes]
) -> str | None:
    text = combined_output(result)
    if result.returncode:
        return text or f"cat exited {result.returncode}"
    if looks_like_file_error(text) and path in text and len(text.splitlines()) == 1:
        return text
    return None


def classify_error(detail: str) -> str:
    lowered = detail.lower()
    if "permission denied" in lowered or "operation not permitted" in lowered:
        return "permission_denied"
    if "no such file" in lowered or "not found" in lowered:
        return "absent"
    return "probe_failed"


def parse_path(spec: PathSpec, text: str) -> PathProbe:
    parts = text.split()
    label_index = next(
        (index for index, part in enumerate(parts) if part.startswith("u:object_r:")),
        None,
    )
    label = parts[label_index] if label_index is not None else None
    size = None
    if label_index is not None and label_index + 1 < len(parts):
        candidate = parts[label_index + 1]
        size = int(candidate) if candidate.isdigit() else None
    return PathProbe(
        spec.name,
        spec.path,
        spec.role,
        "visible",
        mode=parts[0] if parts else None,
        size=size,
        label=label,
    )


def parse_config(raw: bytes) -> dict[str, str]:
    text = gzip.decompress(raw).decode(errors="replace")
    options = {key: "unknown" for key in CONFIG_KEYS}
    for line in text.splitlines():
        enabled = re.fullmatch(r"CONFIG_([A-Z0-9_]+)=(.+)", line)
        disabled = re.fullmatch(r"# CONFIG_([A-Z0-9_]+) is not set", line)
        if enabled and enabled.group(1) in options:
            options[enabled.group(1)] = enabled.group(2)
        if disabled and disabled.group(1) in options:
            options[disabled.group(1)] = "n"
    return options


def parse_kmi(kernel_release: str) -> str | None:
    match = re.search(r"android(\d+)-(\d+\.\d+)", kernel_release)
    return f"android{match.group(1)}-{match.group(2)}" if match else None


def parse_min_api() -> int:
    gradle = (ROOT / "app/build.gradle.kts").read_text()
    match = re.search(r"\bminSdk\s*=\s*(\d+)", gradle)
    if not match:
        raise RuntimeError("could not read minSdk from app/build.gradle.kts")
    return int(match.group(1))


def bundled_modules() -> tuple[list[str], int]:
    module_dir = ROOT / "app/src/main/jni/ko"
    entries: list[tuple[str, int]] = []
    for path in module_dir.glob("dirtyfrag-android*-*.ko"):
        match = re.fullmatch(r"dirtyfrag-(android\d+-\d+\.\d+)\.ko", path.name)
        if match:
            entries.append((match.group(1), path.stat().st_size))
    return sorted(name for name, _ in entries), max((size for _, size in entries), default=0)


def collect_device(adb: Adb) -> dict[str, object]:
    kernel = adb.text("shell", "uname", "-r")
    return {
        "model": adb.property("ro.product.model"),
        "device": adb.property("ro.product.device"),
        "fingerprint": adb.property("ro.build.fingerprint"),
        "android": adb.property("ro.build.version.release"),
        "api": int(adb.property("ro.build.version.sdk")),
        "kernel_release": kernel,
        "kmi": parse_kmi(kernel),
        "identity": adb.text("shell", "id"),
        "selinux": adb.text("shell", "getenforce"),
    }


def collect_config(adb: Adb) -> tuple[dict[str, str] | None, dict[str, object]]:
    probe, raw = adb.read("/proc/config.gz")
    if raw is None:
        return None, probe
    try:
        return parse_config(raw), probe
    except (gzip.BadGzipFile, EOFError) as exc:
        return None, {**probe, "state": "invalid", "detail": str(exc)}


def collect_modules(adb: Adb) -> dict[str, object]:
    probe, raw = adb.read("/proc/modules")
    if raw is None:
        return probe
    lines = raw.decode(errors="replace").splitlines()
    unsigned = []
    for line in lines:
        taint = re.search(r"\(([^)]*)\)\s*$", line)
        if taint and "E" in taint.group(1):
            unsigned.append(line.split()[0])
    return {**probe, "count": len(lines), "unsigned": unsigned}


def collect_scalar(adb: Adb, path: str) -> dict[str, object]:
    probe, raw = adb.read(path)
    return {**probe, "value": raw.decode(errors="replace").strip() if raw else None}


def collect_evidence(serial: str, timeout: int) -> Evidence:
    adb = Adb(serial, timeout)
    kmis, maximum_module_size = bundled_modules()
    config, config_probe = collect_config(adb)
    return Evidence(
        serial=serial,
        device=collect_device(adb),
        config=config,
        config_probe=config_probe,
        modules=collect_modules(adb),
        modules_disabled=collect_scalar(adb, "/proc/sys/kernel/modules_disabled"),
        paths=[adb.path(spec) for spec in PATHS],
        min_api=parse_min_api(),
        bundled_kmis=kmis,
        maximum_module_size=maximum_module_size,
    )


def finding(state: str, name: str, summary: str, next_step: str | None = None) -> Finding:
    return Finding(state, name, summary, next_step)


def check_api(evidence: Evidence) -> Finding:
    api = int(evidence.device["api"])
    if api >= evidence.min_api:
        summary = f"device API {api} satisfies minSdk {evidence.min_api}"
        return finding("pass", "Android API", summary)
    return finding(
        "block",
        "Android API",
        f"device API {api} is below minSdk {evidence.min_api}",
        f"build a separate APK variant with minSdk at or below {api}",
    )


def check_kmi(evidence: Evidence) -> Finding:
    kmi = evidence.device["kmi"]
    if kmi is None:
        return finding(
            "block",
            "Kernel module identity",
            "kernel release has no Android KMI tag",
            "add an exact-firmware target; do not substitute a same-version GKI module",
        )
    if kmi in evidence.bundled_kmis:
        return finding("pass", "Kernel module identity", f"bundled module matches {kmi}")
    return finding(
        "block",
        "Kernel module identity",
        f"no bundled module matches {kmi}",
        f"build and validate an exact {kmi} module",
    )


def check_config(evidence: Evidence) -> Finding:
    if evidence.config is None:
        state = evidence.config_probe["state"]
        return finding(
            "unknown",
            "DirtyFrag kernel prerequisites",
            f"/proc/config.gz is {state}",
            "supply the exact running kernel config before selecting a payload",
        )
    xfrm = evidence.config["XFRM"]
    esp = evidence.config["INET_ESP"]
    if xfrm == "y" and esp in {"y", "m"}:
        return finding("pass", "DirtyFrag kernel prerequisites", f"XFRM={xfrm}, INET_ESP={esp}")
    return finding(
        "block",
        "DirtyFrag kernel prerequisites",
        f"XFRM={xfrm}, INET_ESP={esp}",
        "use a different exploit vector; the required ESP path is absent",
    )


def check_modules(evidence: Evidence) -> Finding:
    if evidence.config is None:
        return finding("unknown", "Loadable modules", "kernel config unavailable")
    value = evidence.config["MODULES"]
    if value == "y":
        return finding("pass", "Loadable modules", "CONFIG_MODULES=y")
    return finding("block", "Loadable modules", f"CONFIG_MODULES={value}")


def check_modules_disabled(evidence: Evidence) -> Finding:
    probe = evidence.modules_disabled
    if probe.get("state") != "readable":
        return finding(
            "unknown",
            "Runtime module loading",
            f"modules_disabled is {probe.get('state')}",
            "read it from the actual loader domain or test finit_module there",
        )
    if probe.get("value") == "0":
        return finding("pass", "Runtime module loading", "kernel.modules_disabled=0")
    return finding(
        "block",
        "Runtime module loading",
        f"kernel.modules_disabled={probe.get('value')}",
    )


def check_signatures(evidence: Evidence) -> Finding:
    if evidence.config is None:
        return finding("unknown", "Module signatures", "kernel config unavailable")
    if evidence.config["MODULE_SIG_FORCE"] == "y":
        return finding(
            "block",
            "Module signatures",
            "CONFIG_MODULE_SIG_FORCE=y",
            "do not attempt the modified-module chain",
        )
    unsigned = evidence.modules.get("unsigned", [])
    if unsigned:
        return finding(
            "pass",
            "Module signatures",
            "unsigned module loaded this boot: " + ", ".join(unsigned),
        )
    return finding(
        "unknown",
        "Module signatures",
        "build config does not force signatures; runtime acceptance is unverified",
        "record the errno from an exact-build finit_module test in the loader domain",
    )


def path_by_name(evidence: Evidence, name: str) -> PathProbe:
    return next(path for path in evidence.paths if path.name == name)


def check_crash_dump(evidence: Evidence) -> Finding:
    configured = path_by_name(evidence, "crash_dump")
    alternative = path_by_name(evidence, "crash_dump_system")
    if configured.state == "visible":
        return finding("pass", "Crash-dump bridge", configured.path)
    if alternative.state == "visible":
        return finding(
            "block",
            "Crash-dump bridge",
            f"configured path is {configured.state}; exact alternative is {alternative.path}",
            "add an exact target that pins the alternative path and file hash",
        )
    state = "unknown" if "permission_denied" in {configured.state, alternative.state} else "block"
    summary = f"configured={configured.state}, alternative={alternative.state}"
    return finding(state, "Crash-dump bridge", summary)


def check_required_paths(evidence: Evidence) -> Finding:
    required = [
        path
        for path in evidence.paths
        if path.role == "required" and path.name != "crash_dump"
    ]
    missing = [path for path in required if path.state != "visible"]
    if not missing:
        return finding("pass", "Required payload paths", "loader and libc++ are visible")
    summary = ", ".join(f"{path.name}={path.state}" for path in missing)
    state = "unknown" if any(path.state == "permission_denied" for path in missing) else "block"
    return finding(state, "Required payload paths", summary)


def check_carrier(evidence: Evidence) -> Finding:
    carriers = [path for path in evidence.paths if path.role == "carrier"]
    compatible = [
        path
        for path in carriers
        if path.state == "visible"
        and path.label == "u:object_r:vendor_file:s0"
        and (path.size or 0) >= evidence.maximum_module_size
    ]
    if compatible:
        chosen = compatible[0]
        summary = f"{chosen.path}, {chosen.size} bytes, {chosen.label}"
        return finding("pass", "Module carrier", summary)
    visible = [path for path in carriers if path.state == "visible"]
    if visible:
        observed = ", ".join(f"{path.name}:{path.label}:{path.size}" for path in visible)
        return finding(
            "block",
            "Module carrier",
            "no configured carrier has vendor_file label and sufficient size; " + observed,
            "add a carrier only after verifying its loader-domain module_load permission",
        )
    state = "unknown" if any(path.state == "permission_denied" for path in carriers) else "block"
    return finding(state, "Module carrier", "no configured carrier is visible")


def check_hardening(evidence: Evidence) -> Finding:
    if evidence.config is None:
        return finding("info", "Kernel hardening", "kernel config unavailable")
    options = evidence.config
    kpti = "on" if options["UNMAP_KERNEL_AT_EL0"] == "y" else "off"
    return finding(
        "info",
        "Kernel hardening",
        f"KPTI={kpti}, KASLR={options['RANDOMIZE_BASE']}, "
        f"kernel_RWX={options['STRICT_KERNEL_RWX']}, module_RWX={options['STRICT_MODULE_RWX']}",
    )


CHECKS: tuple[Callable[[Evidence], Finding], ...] = (
    check_api,
    check_kmi,
    check_config,
    check_modules,
    check_modules_disabled,
    check_signatures,
    check_crash_dump,
    check_required_paths,
    check_carrier,
    check_hardening,
)


def evaluate(evidence: Evidence) -> Report:
    findings = [check(evidence) for check in CHECKS]
    states = {item.state for item in findings}
    verdict = "ready_for_runtime_probe"
    if "unknown" in states:
        verdict = "inconclusive"
    if "block" in states:
        verdict = "blocked"
    return Report(verdict, evidence, findings)


def render_text(report: Report) -> str:
    device = report.evidence.device
    lines = [
        f"DFRoot preflight: {report.verdict}",
        f"device: {device['model']} / {device['device']}",
        f"build: {device['fingerprint']}",
        f"Android/API: {device['android']} / {device['api']}",
        f"kernel: {device['kernel_release']}",
        f"identity: {device['identity']}",
        f"SELinux: {device['selinux']}",
        "",
        "Checks",
    ]
    for item in report.findings:
        lines.append(f"  {item.state.upper():7} {item.name}: {item.summary}")
    lines.extend(("", "Paths"))
    for path in report.evidence.paths:
        metadata = " ".join(
            part
            for part in (
                f"size={path.size}" if path.size is not None else "",
                f"label={path.label}" if path.label else "",
            )
            if part
        )
        lines.append(f"  {path.name}: {path.state} {path.path} {metadata}".rstrip())
    next_steps = list(dict.fromkeys(item.next_step for item in report.findings if item.next_step))
    if next_steps:
        lines.extend(("", "Next steps"))
        lines.extend(f"  {index}. {step}" for index, step in enumerate(next_steps, 1))
    lines.extend(("", "This preflight does not run DirtyFrag or load a module."))
    return "\n".join(lines)


def report_dict(report: Report) -> dict[str, object]:
    return {
        "schema_version": 1,
        "verdict": report.verdict,
        "device": report.evidence.device,
        "dfroot": {
            "min_api": report.evidence.min_api,
            "bundled_kmis": report.evidence.bundled_kmis,
            "maximum_module_size": report.evidence.maximum_module_size,
        },
        "config_probe": report.evidence.config_probe,
        "config": report.evidence.config,
        "modules": report.evidence.modules,
        "modules_disabled": report.evidence.modules_disabled,
        "paths": [asdict(path) for path in report.evidence.paths],
        "findings": [asdict(item) for item in report.findings],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", help="ADB device serial")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--timeout", type=int, default=30)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = evaluate(collect_evidence(args.serial, args.timeout))
    output = render_text(report)
    if args.format == "json":
        output = json.dumps(report_dict(report), indent=2, sort_keys=True)
    print(output)
    return {"ready_for_runtime_probe": 0, "blocked": 2, "inconclusive": 3}[report.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
