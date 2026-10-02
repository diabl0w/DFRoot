#include "elf_hook.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_ops.h"

int find_hook_target(const char *path, const char *symbol,
                     uint64_t *hook, uint64_t *payload, uint32_t *first_insn,
                     struct Reporter *reporter);

int install_elf_hook(struct DirtyFragWriter *writer,
                     const char *path, const char *symbol,
                     char *stage_data, uint32_t stage_length,
                     char *stage_start, char *first_instruction_copy,
                     struct Reporter *reporter,
                     struct PatchRestore *restore) {
    uint64_t hook_offset, payload_offset;
    uint32_t first_instruction;
    if (find_hook_target(path, symbol, &hook_offset, &payload_offset,
                         &first_instruction, reporter) != 0) {
        REPORTLN("ELF hook target lookup failed: %s", path);
        return 1;
    }
    REPORTLN("ELF hook path=%s hook=0x%lx payload=0x%lx len=%u",
             path, hook_offset, payload_offset, stage_length);

    const uint32_t branch_opcode = 0x14000000;
    uint32_t stage_entry = (uint32_t)(stage_start - stage_data);
    uint32_t hook_instruction = branch_opcode
        | (((payload_offset + stage_entry - hook_offset) >> 2) & 0x3ffffff);
    if (first_instruction == hook_instruction) {
        REPORTLN("ELF hook rejected: trampoline is already patched and original bytes cannot be proven");
        REPORTLN("NEXT: reboot or evict the file-backed cache, then rerun exact identity checks");
        return 1;
    }

    uint32_t return_instruction = branch_opcode
        | (((hook_offset + 4) - (payload_offset + stage_length - 4)) >> 2
           & 0x3ffffff);
    *(uint32_t *)&stage_data[stage_length - 4] = return_instruction;
    *(uint32_t *)first_instruction_copy = first_instruction;

    size_t padded_length;
    char *payload = pad16(stage_data, stage_length, &padded_length);
    if (!payload) return -1;

    if (restore) {
        memset(restore, 0, sizeof(*restore));
        restore->path = path;
        restore->payload_offset = payload_offset;
        restore->payload_length = padded_length;
        restore->payload_original = malloc(padded_length);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (!restore->payload_original || fd < 0
                || pread(fd, restore->payload_original, padded_length,
                         (off_t)payload_offset) != (ssize_t)padded_length) {
            free(restore->payload_original);
            restore->payload_original = NULL;
        } else {
            restore->payload_valid = 1;
        }
        if (fd >= 0) close(fd);
        if (!restore->payload_valid) {
            REPORTLN("ELF hook cannot preserve payload bytes: %s", path);
            free(payload);
            return -1;
        }
    }

    REPORTLN("* patching ELF hook payload: %s", path);
    int result = dirtyfrag_patch_file(writer, path, payload, padded_length,
                                      payload_offset, 0, reporter);
    free(payload);
    if (result != 0) return result;

    uint64_t aligned_offset = hook_offset & ~(uint64_t)15;
    int instruction_position = (int)(hook_offset & 15);
    uint8_t block[16];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || pread(fd, block, sizeof(block), (off_t)aligned_offset)
            != (ssize_t)sizeof(block)) {
        REPORTLN("ELF hook trampoline read failed: %s", path);
        if (fd >= 0) close(fd);
        return -1;
    }
    close(fd);
    if (restore) {
        restore->trampoline_offset = aligned_offset;
        memcpy(restore->trampoline_original, block, sizeof(block));
        restore->trampoline_valid = 1;
    }
    memcpy(block + instruction_position, &hook_instruction,
           sizeof(hook_instruction));
    REPORTLN("* patching ELF hook trampoline: %s+0x%lx",
             path, hook_offset);
    return dirtyfrag_patch_file(writer, path, block, sizeof(block),
                                aligned_offset, 0, reporter);
}

int restore_elf_hook(struct DirtyFragWriter *writer,
                     struct PatchRestore *restore,
                     struct Reporter *reporter) {
    int write_result = 0;
    if (restore->trampoline_valid
            && dirtyfrag_patch_file(writer, restore->path,
                    restore->trampoline_original,
                    sizeof(restore->trampoline_original),
                    restore->trampoline_offset, 0, reporter) != 0)
        write_result = -1;
    if (restore->payload_valid && restore->payload_original
            && dirtyfrag_patch_file(writer, restore->path,
                    restore->payload_original, restore->payload_length,
                    restore->payload_offset, 0, reporter) != 0)
        write_result = -1;
    if (!restore->trampoline_valid && !restore->payload_valid) return 0;

    drop_file_cache(restore->path, reporter);
    int fd = open(restore->path, O_RDONLY | O_CLOEXEC);
    int exact = fd >= 0;
    if (exact && restore->trampoline_valid)
        exact = file_span_matches(fd, (off_t)restore->trampoline_offset,
                                  restore->trampoline_original,
                                  sizeof(restore->trampoline_original));
    if (exact && restore->payload_valid)
        exact = file_span_matches(fd, (off_t)restore->payload_offset,
                                  restore->payload_original,
                                  restore->payload_length);
    if (fd >= 0) close(fd);
    REPORTLN("* ELF hook restoration: %s%s",
             exact ? "restored_exact" : "failed_or_ambiguous",
             exact && write_result != 0 ? " (recovered by cache drop)" : "");
    return exact ? 0 : -1;
}

void dispose_elf_hook(struct PatchRestore *restore) {
    free(restore->payload_original);
    memset(restore, 0, sizeof(*restore));
}
