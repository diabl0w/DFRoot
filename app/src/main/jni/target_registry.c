#include "target_registry.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "file_ops.h"

#define PATCH_TARGET(name) extern const struct PatchTarget target_##name;
#define INIT_TARGET(name) extern const struct InitTarget target_##name;
#include "targets/targets.inc"
#undef PATCH_TARGET
#undef INIT_TARGET

const struct PatchTarget *const patch_targets[] = {
#define PATCH_TARGET(name) &target_##name,
#define INIT_TARGET(name)
#include "targets/targets.inc"
#undef PATCH_TARGET
#undef INIT_TARGET
};

const size_t patch_target_count =
    sizeof(patch_targets) / sizeof(patch_targets[0]);

const struct InitTarget *const init_targets[] = {
#define PATCH_TARGET(name)
#define INIT_TARGET(name) &target_##name,
#include "targets/targets.inc"
#undef PATCH_TARGET
#undef INIT_TARGET
};

const size_t init_target_count =
    sizeof(init_targets) / sizeof(init_targets[0]);

struct FileIdentity {
    off_t size;
    uint8_t sha256[32];
    int stat_errno;
    int hash_errno;
};

static int read_identity(const char *path, struct FileIdentity *identity) {
    memset(identity, 0, sizeof(*identity));
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        identity->stat_errno = errno;
        return -1;
    }
    identity->size = file_stat.st_size;
    if (hash_file(path, identity->sha256) != 0) {
        identity->hash_errno = errno;
        return -1;
    }
    return 0;
}

static void digest_hex(const uint8_t digest[32], char output[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        output[i * 2] = digits[digest[i] >> 4];
        output[i * 2 + 1] = digits[digest[i] & 15];
    }
    output[64] = '\0';
}

static void report_identity_mismatch(struct Reporter *reporter,
                                     const char *candidate,
                                     const char *role, const char *path,
                                     off_t expected_size,
                                     const uint8_t expected_sha256[32],
                                     const struct FileIdentity *observed) {
    char expected_hex[65];
    char observed_hex[65];
    digest_hex(expected_sha256, expected_hex);
    digest_hex(observed->sha256, observed_hex);
    if (observed->stat_errno) {
        REPORTLN("candidate %s rejected: %s missing path=%s errno=%d (%s)",
                 candidate, role, path, observed->stat_errno,
                 strerror(observed->stat_errno));
    } else if (observed->hash_errno) {
        REPORTLN("candidate %s rejected: %s unreadable path=%s size=%lld errno=%d (%s)",
                 candidate, role, path, (long long)observed->size,
                 observed->hash_errno, strerror(observed->hash_errno));
    } else if (expected_size >= 0) {
        REPORTLN("candidate %s rejected: %s identity mismatch path=%s observed_size=%lld expected_size=%lld",
                 candidate, role, path, (long long)observed->size,
                 (long long)expected_size);
        REPORTLN("candidate %s observed_%s_sha256=%s expected_%s_sha256=%s",
                 candidate, role, observed_hex, role, expected_hex);
    } else {
        REPORTLN("candidate %s rejected: %s identity mismatch path=%s observed_size=%lld",
                 candidate, role, path, (long long)observed->size);
        REPORTLN("candidate %s observed_%s_sha256=%s expected_%s_sha256=%s",
                 candidate, role, observed_hex, role, expected_hex);
    }
}

const struct InitTarget *find_init_target(struct Reporter *reporter) {
    struct utsname identity;
    if (uname(&identity) != 0) return NULL;
    int kernel_candidates = 0;
    for (size_t i = 0; i < init_target_count; i++) {
        const struct InitTarget *target = init_targets[i];
        if (strcmp(identity.release, target->kernel_release) != 0) continue;
        kernel_candidates++;
        struct FileIdentity observed;
        if (read_identity(target->carrier_path, &observed) != 0
                || memcmp(observed.sha256, target->carrier_sha256, 32) != 0) {
            report_identity_mismatch(reporter, target->id, "carrier",
                                     target->carrier_path, (off_t)-1,
                                     target->carrier_sha256, &observed);
            continue;
        }
        REPORTLN("exact init target: %s carrier=%s size=%lld sha256=exact",
                 target->id, target->carrier_path, (long long)observed.size);
        return target;
    }
    if (kernel_candidates == 0)
        REPORTLN("init strategy: no descriptor declares kernel_release=%s",
                 identity.release);
    else
        REPORTLN("NEXT: preserve the observed carrier size/SHA-256, then derive and verify the hook against that exact ELF build");
    return NULL;
}

const struct PatchTarget *find_patch_target(struct Reporter *reporter) {
    struct utsname identity;
    if (uname(&identity) != 0) return NULL;
    REPORTLN("observed kernel release: %s", identity.release);
    int kernel_candidates = 0;
    for (size_t i = 0; i < patch_target_count; i++) {
        const struct PatchTarget *target = patch_targets[i];
        if (strcmp(identity.release, target->kernel_release) != 0) continue;
        kernel_candidates++;
        struct FileIdentity observed;
        if (read_identity(target->bridge_path, &observed) != 0
                || observed.size != target->bridge_size
                || memcmp(observed.sha256, target->bridge_sha256, 32) != 0) {
            report_identity_mismatch(reporter, target->id, "bridge",
                                     target->bridge_path, target->bridge_size,
                                     target->bridge_sha256, &observed);
            continue;
        }
        REPORTLN("exact patch target candidate: %s bridge=%s size=%lld sha256=exact",
                 target->id, target->bridge_path, (long long)observed.size);
        REPORTLN("candidate %s protected_path=%s expected_size=%lld byte_guards=deferred_until_bridge",
                 target->id, target->target_path,
                 (long long)target->target_size);
        return target;
    }
    if (kernel_candidates == 0) {
        REPORTLN("patch strategy: no descriptor declares kernel_release=%s",
                 identity.release);
        REPORTLN("NEXT: capture an executable bridge path/size/SHA-256 and exact protected-file build ID, EOF block, patch preimages, and replacement instructions");
    } else {
        REPORTLN("NEXT: preserve the observed bridge binary and add a descriptor only after its full identity and protected-file guards are derived");
    }
    return NULL;
}
