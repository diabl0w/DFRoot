# android11-5.4 / Samsung SM-T733 (Galaxy Tab S7 FE)

Notes for the `android11-5.4` KMI added in this tree. Read this before shipping a
`.ko` for it: 5.4 is GKI 1.0, so unlike every other entry in `KMIS` this image is
**built for one device**.

## Target

| | |
|---|---|
| Device | Samsung Galaxy Tab S7 FE, SM-T733 |
| Firmware | `T733XXS9DYF1` — Android 14 / One UI 6.1, security patch 2025-06-01 (final firmware for the model) |
| `uname -r` | `5.4.254-qgki-28692233-abT733XXS9DYF1` |
| KMI | `android11-5.4` (GKI 1.0, vendor-modified qgki; `ro.board.first_api_level=30`) |
| Kernel vermagic | `5.4.254-qgki-28692233-abT733XXS9DYF1 SMP preempt mod_unload modversions aarch64` |
| Kernel compiler | Android clang `r383902b1`, 11.0.2 (build 6877366) |

## Why there is no DDK image

`make ENGINE=docker|podman` builds every other KMI from
`ghcr.io/ylarod/ddk-min:<kmi>-<release>`. Those images cover GKI 2.0 KMIs, where
Google guarantees a stable module interface. 5.4 predates that guarantee: a
module must match the device kernel's symbol CRCs and struct layouts, so it has
to be built against that device's source and config. There is no
`android11-5.4` DDK image, and adding the KMI to `KMIS` or the CI matrix will
fail — build the `.ko` by hand and drop it in `app/src/main/jni/ko/`.

## Building the module

Kernel source for this exact build (public, GPLv2):
`github.com/ssch71/android_kernel_samsung_gts7fewifi_SM7325`, branch `main`.
Its initial commit is "initial: SM-T733 kernel source T733XXS9DYF1", and the
`boot.img` it carries reports `Linux version 5.4.254-qgki-28692233-abT733XXS9DYF1
... #1 SMP PREEMPT Thu Jun 19 22:10:26 KST 2025` — the same compile stamp the
tablet reports, so it is the same build rather than a near-miss.

Defconfig: `arch/arm64/configs/vendor/gts7fewifi_eur_open_defconfig`.

Relevant settings in that defconfig:

| Knob | Value | Why it matters |
|---|---|---|
| `CONFIG_MODVERSIONS` | y | symbol CRCs enforced; `same_magic()` then ignores the release string, so only the flags must match |
| `CONFIG_MODULE_SIG` | unset | unsigned modules load |
| `CONFIG_MODULE_FORCE_LOAD` | unset | a mismatch fails cleanly |
| `CONFIG_KPROBES` / `CONFIG_KALLSYMS_ALL` | y | `register_kprobe` finds `kallsyms_lookup_name`; data symbols resolve |
| `CONFIG_LTO_CLANG` / `CONFIG_THINLTO` / `CONFIG_CFI_CLANG` | y | the module must be compiled by a clang that can emit kernel CFI |
| `CONFIG_STATIC_USERMODEHELPER` | y | `lkm/dfroot.c` overwrites `subprocess_info->path`; load-bearing here |
| `CONFIG_SECURITY_SELINUX_DISABLE` | unset | combined with Samsung's porting change, this is why `selinux_enforcing` must be written — see the `lkm` commit |
| `CONFIG_DEBUG_INFO` | y | strip `.debug_*` or the module will not fit the vendor library |

Steps:

```sh
git clone --depth 1 https://github.com/ssch71/android_kernel_samsung_gts7fewifi_SM7325 ktree
make -C ktree O=$PWD/kout ARCH=arm64 vendor/gts7fewifi_eur_open_defconfig
# DEBUG_INFO only bloats the .ko; it changes no CRC and no vermagic
ktree/scripts/config --file kout/.config --disable DEBUG_INFO
make -C ktree O=$PWD/kout ARCH=arm64 olddefconfig
make -C ktree O=$PWD/kout ARCH=arm64 -j$(nproc) \
     CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy \
     OBJDUMP=llvm-objdump STRIP=llvm-strip modules
make -C ktree O=$PWD/kout M=$PWD/lkm ARCH=arm64 \
     CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy \
     OBJDUMP=llvm-objdump STRIP=llvm-strip modules
```

The module itself needs no source changes for this kernel: `struct
subprocess_info` keeps `path` as its third member, `aarch64_insn_patch_text(void
*addrs[], u32 insns[], int cnt)` is unchanged, `__nocfi` exists, and `struct
kprobe` still has `.symbol_name` / `.addr`.

## Two build-level caveats

**No `Module.symvers`, no CRCs.** Building the module without a full kernel
build leaves `__versions` empty, and a `CONFIG_MODVERSIONS` kernel refuses a
module with no `__versions` section at all (`versindex == 0` goes to
`try_to_force_load()`, which fails). It does *not* refuse a module that has the
section but omits a symbol — `check_version()` takes
`pr_warn_once("no symbol version for %s")` and returns 1. So a single
placeholder `struct modversion_info` record is enough, and every import warns in
`dmesg` instead of being CRC-checked.

**CFI.** With `CONFIG_CFI_CLANG=y`, `module_finalize()` sets
`mod->cfi_check = find_kallsyms_symbol_value(mod, "__cfi_check")`;
`add_module_to_shadow()` returns early when that is NULL, and
`__cfi_slowpath()` then reaches `handle_cfi_failure()` →
`panic("CFI failure")` because `CONFIG_CFI_PERMISSIVE` is unset. So the module
must carry a `__cfi_check`. If it was compiled by a clang that no longer emits
kernel CFI (`-fsanitize=cfi` was removed upstream in favour of `kcfi`, so
clang 21 rejects it), graft a page-aligned stub:

```asm
        .text
        .balign 4096
        .globl __cfi_check
__cfi_check:
        ret
```

A strong definition overrides the weak one clang may have left behind. This
makes the module loadable but means the kernel does not type-check calls into
it — prefer building with the kernel's own compiler (`r383902b1`) when you can.

## Evidence

Working module: 16,968 bytes, `ET_REL`/`EM_AARCH64`, `__versions` = one 64-byte
placeholder record, `__cfi_check` at `0x1000` = `ret`, `.text` aligned 4096,
imports only `printk memset snprintf __stack_chk_fail __stack_chk_guard
register_kprobe unregister_kprobe` (all exported by this kernel). On-device run:

```
Using KMI: android11-5.4
patch: /vendor/lib64/libstagefrighthw.so <- dfroot.ko (16976 bytes)
libc++: loading custom module
kernel module: launching bootstrap
bootstrap: starting SU daemon
ksud start: SUCCESS
```

Note the SU manager is stock KernelSU (`me.weishu.kernelsu`, manager
`samsung-v2.2`); the fork is not required for the exploit itself.

## Limitations of this KMI

* The image is device-specific and must not be shipped to other 5.4 devices.
  If it is added to a release, gate it on `ro.product.model`.
* KernelSU's driver cannot load (no `kernelsu.ko` for non-GKI), so the manager
  reports "Unsupported" and it provides no `su`. `/data` is also mounted
  `nosuid` on this device, which rules out a setuid binary, so a userspace `su`
  daemon is the only way to use a session from an app. That daemon is not part
  of this change.
* Root lasts until reboot: the module is never installed, and the SELinux change
  is a RAM write.
