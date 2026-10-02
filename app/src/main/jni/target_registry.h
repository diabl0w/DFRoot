#ifndef DFROOT_TARGET_REGISTRY_H
#define DFROOT_TARGET_REGISTRY_H

#include "root_target.h"
#include "reporter.h"

extern const struct PatchTarget *const patch_targets[];
extern const size_t patch_target_count;
extern const struct InitTarget *const init_targets[];
extern const size_t init_target_count;

const struct PatchTarget *find_patch_target(struct Reporter *reporter);
const struct InitTarget *find_init_target(struct Reporter *reporter);

#endif
