#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"
#include "psk.h"

size_t psk_load(const char *path, uint8_t buf[PSK_MAX_LEN]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        die("cannot open key file %s: %s", path, strerror(errno));

    struct stat sb;
    if (fstat(fd, &sb) < 0)
        die("stat %s: %s", path, strerror(errno));
    if (!S_ISREG(sb.st_mode))
        die("key file %s is not a regular file", path);
    if (sb.st_mode & (S_IRWXG | S_IRWXO))
        die("key file %s is accessible by group/others; run: chmod 600 %s", path, path);

    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, buf + n, PSK_MAX_LEN - n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            die("read %s: %s", path, strerror(errno));
        if (r == 0)
            break;
        n += (size_t)r;
        if (n == PSK_MAX_LEN)
            die("key file %s is larger than %d bytes", path, PSK_MAX_LEN - 1);
    }
    close(fd);

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
        n--;
    if (n < PSK_MIN_LEN)
        die("key in %s is too short (%zu bytes, need %d); generate one with:\n"
            "    (umask 077; head -c 32 /dev/urandom | base64 > %s)",
            path, n, PSK_MIN_LEN, path);
    return n;
}
