> [!IMPORTANT]
> If you want to use your own ksud binary, you must compile from my fork: https://github.com/diabl0w/KernelSU

# DFRoot [DirtyFrag (CVE-2026-43284)]

The core of this code is fully credited to others. I merely combined ideas to make them all better 
and added some small improvements/features. 

Credits:
- Original PoC and various code: https://github.com/lsposed/lspromise
- Selinux Permissive kernel modules and various code: https://github.com/polygraphene/DFReroot
- Unprivileged XFRM socket method: https://github.com/combeng6th/DirtyInit

## Features

- Start on Boot
- Automatic soft reboot 
- RO Partition Protection
- Hide Selinux Modifications in KSU
- Shizuku not needed — regain root without WiFi!

> [!WARNING]
> I am not responsible for any damage to your device.

## Supported Devices

Ephemeral root for compatible Android devices with locked bootloaders that are
vulnerable to DirtyFrag (CVE-2026-43284). Vendor kernels used by Android-based
XR devices often differ from phone GKI builds even when their Android and Linux
versions look similar, so compatibility is established per exact firmware.

| KMI Version | Verified |
|---|---|
| android12-5.10 | Untested |
| android13-5.10 | Untested |
| android13-5.15 | Untested |
| android14-5.15 | Untested |
| android14-6.1 | Untested |
| android15-6.6 | Yes |
| android16-6.12 | Yes |
| android17-6.18 | Untested |

## Compatibility preflight and new firmware ports

Run the read-only preflight before attempting the payload:

```sh
python3 tools/device_preflight.py ADB_SERIAL
```

Use `--format text` for a concise operator report. The default JSON form is
intended for scripts and agent handoffs. When an exact-build symbol map and raw
uncompressed kernel Image are available, pass them explicitly:

```sh
python3 tools/device_preflight.py ADB_SERIAL \
  --symbol-map /path/to/System.map \
  --kernel-image /path/to/Image \
  --format text
```

It reports the full build identity, Android API, kernel release and KMI tag,
SELinux state, configured and alternative paths, readable file hashes, a
bounded summary of shell-visible carrier labels, relevant kernel config, and
module-signature policy. Its ordered `next_steps` explain which evidence led
to each recommendation and mark hard stops separately from useful follow-up
probes. Exit code 2 means a prerequisite is known to be absent. Exit code 3
means a required property remains unverified. A clean preflight does not prove
that DirtyFrag is present or that the modified module will load.

### Scratch-only primitive proof

The app's **Probe Primitive (Scratch Only)** action tests the DirtyFrag write
against a newly created 4096-byte file in the app's private data directory. It
writes one known 16-byte block through the XFRM/ESP path, compares the observed
bytes, restores the original bytes through the ordinary owned-file path,
flushes and reopens the file, verifies the restoration, and deletes the file.
It does not patch a system or vendor file and does not attempt to load a module.

After running the action, rerun `device_preflight.py`. The tool reads the
machine-readable result with `run-as`, verifies that its full build fingerprint
and kernel release match the connected device, and reports the before,
requested/observed, and reopened-after-restore byte strings. A confirmed result
establishes only the page-cache write primitive on that exact running firmware;
it does not establish a privileged trigger, root, module compatibility, module
signature acceptance, or persistence.

The symbol report keeps offline addresses, `_text`-relative offsets, raw Image
byte windows, the live KASLR base, and computed live addresses separate. A byte
window is useful only when the Image hash and its file-offset mapping are both
verified. An offline offset must never be printed as a live address. For data
symbols such as `selinux_state`, also verify the exact-build structure layout
and field offset; finding the symbol does not identify which byte controls the
intended field.

Path states are intentionally three-valued: `visible`, `absent`, or
`permission_denied`. Android may hide a real vendor file from the ADB shell,
so the last state must not be reported as absence. Likewise, the carrier scan
is only a view of top-level files visible from the shell and may be bounded by
`--carrier-scan-limit`. The runtime selector logs the size and SELinux label of
each configured candidate and rejects candidates whose label is incompatible
with the hard-coded loader domain. Before adding a new candidate, verify its
contents, type, loader-domain permission, complete readback, and restoration
from the actual privileged execution path.

The report also separates common dynamic loader results. An SELinux
`module_load` denial means the signature verifier was not yet reached;
`ENOKEY` confirms signature rejection; and an invalid-module result points
back to exact kernel identity, vermagic, symbol CRCs, architecture, structure
layout, or CFI assumptions.

For vendor non-GKI builds or blocked module carriers, the report also lists
standard executables that can be started as fresh processes. These are
metadata-only candidates. A useful test extracts the exact protected binary
when policy hides it, pins its full hash and executable prefix, applies a
bounded harmless payload, triggers one fresh process, and restores every byte.
Record the process UID, capabilities, SELinux domain, and raw syscall results.
Before restarting a daemon, record every reachable transport and preserve a
fallback connection. A fresh UID 0 process can still lack the SELinux rules
needed for PMU, GPU, debugfs, sysctl, or module access, so each interface needs
its own functional probe.

Keep these compatibility gates separate when adding a firmware:

1. **Exact target identity.** Record the full build fingerprint, incremental
   build, kernel release, and hashes of the boot/kernel image and chosen carrier.
   Validate expected carrier bytes before writing them.
2. **Kernel module identity.** Use only an exact Android KMI module. Never fall
   back to a module that merely shares the same Linux major/minor version.
   Vendor non-GKI kernels need an exact-build module with matching vermagic,
   symbol CRCs, struct layout, and control-flow integrity compatible symbol
   resolution.
3. **Primitive.** Prove the page-cache write on a harmless scratch target for
   the exact build. Successful offline offset extraction is not this proof.
4. **Loader path.** Verify the actual paths, SELinux transitions, carrier size
   and label, and read back the complete poisoned module before triggering it.
5. **Module policy.** Treat `CONFIG_MODULE_SIG_FORCE=y`,
   `kernel.modules_disabled=1`, or an observed `finit_module` signature error as
   a hard blocker for this module-based chain. If the config is unavailable or
   enforcement is not forced there, keep the result unverified until a harmless
   equivalently modified exact-build module reaches the same loader path.
6. **Outcome.** Report UID, SELinux domain, SELinux enforcing state, module
   state, and KernelSU availability separately. A UID 0 userspace process does
   not by itself prove unrestricted kernel access or persistent root.

## How it works

The Android kernel decrypts AES-CBC ESP packets directly into the page cache of files open for `splice()`. By crafting `IV = AES_ECB_DEC(key, current_content) ⊕ desired_content`, any 16-byte-aligned block in a mapped shared library can be overwritten without write permission and without copy-on-write.

The exploit uses this primitive to patch shellcode into `libc++.so` in the
kernel's page cache. The next privileged call to that function runs the
shellcode, loads the bundled module, and installs KernelSU.

### Exploit chain

1. **IpSec transform** — App allocates a `UdpEncapsulationSocket` + SPI and builds an AES-CBC/HMAC-SHA256 ESP transform via `IpSecManager`.

2. **splicehelper → crash_dump64** — helper binary spliced into `/apex/com.android.runtime/bin/crash_dump64` via the CBC primitive. `crash_dump64` can be called by unprivileged app with `type_transform` and gives read access to vendor library pages and splices them into a pipe so the parent can compute correct IVs. 

3. **dirtyfrag.ko → libbinderdebug.so** — The kernel module is written into `/vendor/lib64/libbinderdebug.so` with `vendor_file` label that can be modprobe'd

4. **libc++ hook** (runs in init, uid=0, tid=1) — the patched function invokes
   `/vendor/bin/insmod` on the poisoned carrier.

5. **Kernel module** — the module changes the required kernel state and starts
   the staged KernelSU daemon.

6. **Cleanup** — the libc++ patch is restored and crash_dump64 is advised out
   of the page cache.

## Usage

Install KernelSU Manager (download & unzip manager file) from actions flow: 
https://github.com/tiann/KernelSU/actions/runs/35973514328

```sh
./build.sh
adb install -r dirtyfrag.apk
```
