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

It reports the full build identity, Android API, kernel release and KMI tag,
SELinux state, required paths, readable carrier hashes, relevant kernel config,
and module-signature policy. Exit code 2 means a prerequisite is known to be
absent. Exit code 3 means a required property remains unverified. A clean
preflight does not prove that DirtyFrag is present or that the modified module
will load.

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
