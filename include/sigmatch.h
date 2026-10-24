#ifndef SIGMATCH_H
#define SIGMATCH_H

#include <stddef.h>
#include <stdint.h>

#define SIG_MSG_MAX     128
#define SIG_CONTENT_MAX 256

struct sig_rule {
    unsigned sid;
    char     msg[SIG_MSG_MAX];
    uint8_t  content[SIG_CONTENT_MAX];
    size_t   len;
};

struct sig_matcher;

/* offset = where the match starts in the scanned buffer */
typedef void (*sig_hit_fn)(const struct sig_rule *rule, size_t offset, void *ctx);

struct sig_matcher *sig_load(const char *path);
void sig_scan(struct sig_matcher *m, const uint8_t *data, size_t len,
              sig_hit_fn hit, void *ctx);
void sig_free(struct sig_matcher *m);

#endif /* SIGMATCH_H */
