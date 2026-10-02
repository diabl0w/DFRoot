#include "file_ops.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hmac_sha256.h"

char *pad16(const char *data, size_t length, size_t *padded_length) {
    size_t padded = (length + 15) & ~(size_t)15;
    char *buffer = calloc(1, padded);
    if (buffer) memcpy(buffer, data, length);
    *padded_length = padded;
    return buffer;
}

int hash_file(const char *path, uint8_t digest[32]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    sha256_ctx context;
    sha256_init(&context);
    uint8_t buffer[8192];
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) > 0)
        sha256_update(&context, buffer, (size_t)count);
    int saved_errno = errno;
    close(fd);
    if (count < 0) {
        errno = saved_errno;
        return -1;
    }
    sha256_final(&context, digest);
    return 0;
}

int file_span_matches(int fd, off_t offset, const void *expected, size_t length) {
    void *observed = malloc(length);
    if (!observed) return 0;
    int matches = pread(fd, observed, length, offset) == (ssize_t)length
        && memcmp(observed, expected, length) == 0;
    free(observed);
    return matches;
}

int drop_file_cache(const char *path, struct Reporter *reporter) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        REPORTLN("cache drop open %s failed: %s", path, strerror(errno));
        return -1;
    }
    int advice = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    int close_result = close(fd);
    if (advice != 0) {
        REPORTLN("cache drop advise %s failed: %s", path, strerror(advice));
        return -1;
    }
    if (close_result != 0) {
        REPORTLN("cache drop close %s failed: %s", path, strerror(errno));
        return -1;
    }
    REPORTLN("* cache dropped: %s", path);
    return 0;
}
