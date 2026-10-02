#ifndef DFROOT_DIRTYFRAG_WRITER_H
#define DFROOT_DIRTYFRAG_WRITER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "reporter.h"

struct DirtyFragWriter {
    int encap_port;
    int sender_port;
    uint32_t spi;
    uint8_t aes_key[32];
    uint8_t hmac_key[32];
    int icv_length;
    uint32_t sequence;
    const char *bridge_path;
    const char *protected_path;
};

void dirtyfrag_writer_init(struct DirtyFragWriter *writer,
                           int encap_port, int sender_port, uint32_t spi,
                           const uint8_t aes_key[32],
                           const uint8_t hmac_key[32], int icv_length);
void dirtyfrag_writer_set_paths(struct DirtyFragWriter *writer,
                                const char *bridge_path,
                                const char *protected_path);
int dirtyfrag_read_protected(struct DirtyFragWriter *writer, off_t offset,
                             uint8_t bytes[16], struct Reporter *reporter);
int dirtyfrag_drop_protected_cache(struct DirtyFragWriter *writer,
                                   struct Reporter *reporter);
int dirtyfrag_patch_file(struct DirtyFragWriter *writer, const char *path,
                         const void *payload, size_t length, size_t offset,
                         int use_bridge, struct Reporter *reporter);

#endif
