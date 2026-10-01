#!/usr/bin/env python3
"""Read-only DFRoot compatibility report for an ADB-attached Android device.

The report checks packaged-payload prerequisites. It does not test the
DirtyFrag primitive, load a module, or change the device.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXP = (ROOT / "app/src/main/jni/exp.c").read_text()
JAVA = (ROOT / "app/src/main/java/df/root/ExploitRunner.java").read_text()
GRADLE = (ROOT / "app/build.gradle.kts").read_text()


def adb(serial: str, *args: str, binary: bool = False):
    result = subprocess.run(
        ["adb", "-s", serial, *args],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace").strip())
    return result.stdout if binary else result.stdout.decode(errors="replace").strip()


def shell(serial: str, *args: str) -> str:
    return adb(serial, "shell", *args)


def present(serial: str, path: str) -> bool:
    return shell(
        serial, "test", "-e", path, "-o", "-L", path,
        "&&", "echo", "yes", "||", "echo", "no",
    ) == "yes"


def file_fingerprint(serial: str, path: str) -> dict[str, object]:
    result: dict[str, object] = {"path": path, "present": present(serial, path)}
    if not result["present"]:
        return result
    try:
        raw = adb(serial, "exec-out", "cat", path, binary=True)
        result["size"] = len(raw)
        result["sha256"] = hashlib.sha256(raw).hexdigest()
    except RuntimeError:
        result["sha256"] = None
    return result


def config_value(config: str, key: str) -> str:
    match = re.search(rf"^CONFIG_{re.escape(key)}=(.+)$", config, re.M)
    return match.group(1) if match else "n"


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

    bundled_kmis = sorted({
        (int(a), int(b), int(c))
        for a, b, c in re.findall(
            r"\{\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*dirtyfrag_ko_", EXP
        )
    })
    kmi_match = re.search(r"android(\d+)-(\d+)\.(\d+)", kernel)
    device_kmi = tuple(map(int, kmi_match.groups())) if kmi_match else None

    required_paths = {
        "crash_dump": "/apex/com.android.runtime/bin/crash_dump64",
        "insmod": "/vendor/bin/insmod",
        "libcxx": "/system/lib64/libc++.so",
    }
    required = {
        name: {"path": path, "present": present(serial, path)}
        for name, path in required_paths.items()
    }
    carrier_paths = sorted(set(re.findall(r'"(/vendor/lib64/[^"\n]+\.so)"', JAVA)))
    carriers = [file_fingerprint(serial, path) for path in carrier_paths]

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

    try:
        modules_disabled = int(shell(serial, "cat", "/proc/sys/kernel/modules_disabled"))
    except (RuntimeError, ValueError):
        modules_disabled = None

    blockers: list[str] = []
    unknowns: list[str] = []
    if sdk < min_sdk:
        blockers.append(f"APK minSdk {min_sdk} exceeds device API {sdk}")
    if device_kmi is None:
        blockers.append(
            "kernel release has no androidNN-X.Y KMI tag; an explicit exact-firmware "
            "target and module are required"
        )
    elif device_kmi not in bundled_kmis:
        blockers.append(
            "no exact bundled module for "
            f"android{device_kmi[0]}-{device_kmi[1]}.{device_kmi[2]}"
        )
    for name, info in required.items():
        if not info["present"]:
            blockers.append(f"required path absent: {name} ({info['path']})")
    if not any(item["present"] for item in carriers):
        blockers.append("none of the supported vendor carrier paths exists")
    if modules_disabled == 1:
        blockers.append("kernel.modules_disabled is 1")
    elif modules_disabled is None:
        unknowns.append("kernel.modules_disabled could not be read")

    if options is None:
        unknowns.append("/proc/config.gz unavailable; kernel prerequisites and signature policy unverified")
        module_signature_policy = "unknown"
    else:
        if options["XFRM"] != "y" or options["INET_ESP"] not in ("y", "m"):
            blockers.append("XFRM/INET_ESP kernel prerequisite absent")
        if options["MODULES"] != "y":
            blockers.append("loadable kernel modules are disabled in the build")
        if options["MODULE_SIG_FORCE"] == "y":
            blockers.append("kernel enforces module signatures; the modified bundled LKM cannot load")
            module_signature_policy = "rejects modified or unsigned modules"
        else:
            module_signature_policy = "not forced by config"
            unknowns.append(
                "modified-module acceptance still needs an exact-firmware finit_module test"
            )

    if blockers:
        assessment = "payload prerequisites unmet"
        exit_code = 2
    elif unknowns:
        assessment = "payload prerequisites inconclusive"
        exit_code = 3
    else:
        assessment = "payload prerequisites present; vulnerability and module load remain untested"
        exit_code = 0

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
            "device_kmi": (
                f"android{device_kmi[0]}-{device_kmi[1]}.{device_kmi[2]}"
                if device_kmi else None
            ),
            "bundled_kmis": [f"android{a}-{b}.{c}" for a, b, c in bundled_kmis],
        },
        "required_paths": required,
        "carrier_candidates": carriers,
        "kernel_options": options,
        "modules_disabled": modules_disabled,
        "module_signature_policy": module_signature_policy,
        "blockers": blockers,
        "unknowns": unknowns,
        "assessment": assessment,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
