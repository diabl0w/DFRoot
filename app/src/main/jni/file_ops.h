#ifndef DFROOT_FILE_OPS_H
#define DFROOT_FILE_OPS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "reporter.h"

char *pad16(const char *data, size_t length, size_t *padded_length);
int hash_file(const char *path, uint8_t digest[32]);
int file_span_matches(int fd, off_t offset, const void *expected, size_t length);
int drop_file_cache(const char *path, struct Reporter *reporter);

#endif
