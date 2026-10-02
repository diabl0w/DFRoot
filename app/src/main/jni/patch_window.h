#ifndef DFROOT_PATCH_WINDOW_H
#define DFROOT_PATCH_WINDOW_H

#include "dirtyfrag_writer.h"
#include "root_target.h"

int run_patch_window(struct DirtyFragWriter *writer,
                     const struct PatchTarget *target,
                     const char *state_path, int window_ms,
                     struct Reporter *reporter);

#endif
