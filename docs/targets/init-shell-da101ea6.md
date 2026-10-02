# `init-shell-da101ea6`

## Evidence state

The predecessor exact-build port live verified this carrier and init-hook
route on successive boots. It produced a UID 0 command channel with group
`shell`, full effective capabilities, the `shell` SELinux domain, and SELinux
still enforcing. The composed target in this branch embeds the command script
and must remain marked for fleet retest until that APK has repeated the result
and reported exact hook restoration.

## Identity

- Kernel release: `4.19.81-perf+`
- Carrier: `/system/lib64/libc++.so`
- Carrier SHA-256: `da101ea6af2028a77f460ec9166e290c771d9cc2a21dce3c269c83b283c4fba8`
- Hook symbol: `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_`
- Observed hook offset in the exact carrier: `0x7d61c`
- Observed payload cave offset in the exact carrier: `0xc4180`

The runtime hashes the complete carrier before resolving the symbol and code
cave. It does not reuse these observed offsets as a fallback when the hash or
kernel release differs.

## Runtime result

The hook runs only in UID 0, TID 1. It forks a child, writes the embedded
command script, changes the child's group to `shell`, requests the `shell`
execution context, and starts `/system/bin/sh`. The channel exposes its status
at `/data/local/tmp/dfroot-shell/status` and sets
`debug.dfroot.ready=1` only after setup succeeds.

The payload records separate failure markers for script creation, group
change, SELinux transition, and `execve`. The hook payload and trampoline are
preserved before the write, restored after the trigger, evicted from the file
cache, and checked against their original bytes.

## Required final acceptance

1. Kernel release and complete carrier SHA-256 match.
2. The root channel reports UID, GID, capabilities, and SELinux context.
3. The app reports `restored_exact` for both payload and trampoline.
4. A reboot returns the original complete carrier SHA-256.
