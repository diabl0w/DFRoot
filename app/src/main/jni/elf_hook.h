#ifndef DFROOT_ELF_HOOK_H
#define DFROOT_ELF_HOOK_H

#include <stddef.h>
#include <stdint.h>

#include "dirtyfrag_writer.h"

struct PatchRestore {
    const char *path;
    uint64_t payload_offset;
    size_t payload_length;
    char *payload_original;
    uint64_t trampoline_offset;
    uint8_t trampoline_original[16];
    int payload_valid;
    int trampoline_valid;
};

int install_elf_hook(struct DirtyFragWriter *writer,
                     const char *path, const char *symbol,
                     char *stage_data, uint32_t stage_length,
                     char *stage_start, char *first_instruction_copy,
                     struct Reporter *reporter,
                     struct PatchRestore *restore);
int restore_elf_hook(struct DirtyFragWriter *writer,
                     struct PatchRestore *restore,
                     struct Reporter *reporter);
void dispose_elf_hook(struct PatchRestore *restore);

#endif
