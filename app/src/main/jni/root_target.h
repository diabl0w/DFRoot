#ifndef DFROOT_ROOT_TARGET_H
#define DFROOT_ROOT_TARGET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct PatchBlock {
    size_t offset;
    uint8_t original[16];
    uint8_t replacement[16];
    const char *purpose;
};

struct PatchTarget {
    const char *id;
    const char *kernel_release;
    const char *bridge_path;
    off_t bridge_size;
    uint8_t bridge_sha256[32];
    const char *target_path;
    off_t target_size;
    const struct PatchBlock *guards;
    size_t guard_count;
    const struct PatchBlock *patches;
    size_t patch_count;
};

struct InitTarget {
    const char *id;
    const char *kernel_release;
    const char *carrier_path;
    uint8_t carrier_sha256[32];
    const char *hook_symbol;
};

#endif
