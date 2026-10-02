#ifndef DFROOT_ROOT_RUNTIME_H
#define DFROOT_ROOT_RUNTIME_H

#include "dirtyfrag_writer.h"
#include "root_target.h"

int run_module_strategy(struct DirtyFragWriter *writer,
                        const char *ko_target, int soft_reboot,
                        struct Reporter *reporter);
int run_init_strategy(struct DirtyFragWriter *writer,
                      const struct InitTarget *target,
                      struct Reporter *reporter);

#endif
