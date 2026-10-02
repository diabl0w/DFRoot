# `adbd-fd30e626`

## Identity

- Kernel release: `4.19.81-perf-dirty`
- Target: `/system/bin/adbd`
- Target size: `30128`
- Target SHA-256: `5f4779e7c29c2d28067c3b1bc97fd843201ce442772013ed12ef3b79786cd4ff`
- ELF build ID: `fd30e626ae885eedc14ed68be968dd3a`
- Bridge: `/system/bin/crash_dump64`
- Bridge size: `132072`
- Bridge SHA-256: `0ccef435afa1ddaee7c7f81744c782dec012a025c9e5ea775714b980c9174af8`

## Guarded changes

The descriptor changes two aligned 16-byte blocks for one newly executed
daemon:

1. At file offset `0x22bc`, replace `orr w21, w10, w9` with `mov w21, wzr`.
   This forces the computed privilege-drop result to false.
2. At file offset `0x2410`, replace `cbz x0, 0x2428` with `b 0x2428`.
   This skips a `selinux_android_setcon(root_seclabel)` call that is denied by
   the installed policy.

The full build-ID blocks, final file block, and both patch preimages must match
before either replacement is attempted.

## Measured result

The two-block transaction was read back while armed. A fresh daemon reported
UID 0, and the subsequent shell reported UID 0 in the `shell` SELinux domain.
Both protected blocks and the bridge prefix were restored exactly. SELinux
remained enforcing, so UID, domain, capabilities, and individual privileged
operations still need separate checks.

The composed foreground-service implementation repeated this result after the
strategy refactor. The daemon PID changed across the trigger, the fresh shell
reported `uid=0(root)` with `u:r:shell:s0`, and the terminal watchdog state was
`result=10`, `target_bytes=restored_exact`, and `bridge=restored_exact`. The
bridge returned to the SHA-256 above. Direct target hashing remained denied by
the enforcing `shell` policy, so the protected bridge readback of the build ID,
EOF, and both original patch blocks is the target restoration proof.
