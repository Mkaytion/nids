#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sigmatch.h"

/*
 * Aho-Corasick: every rule is compiled into one automaton, so a payload is
 * scanned in a single pass no matter how many rules are loaded.
 */

struct sig_matcher {
    struct sig_rule *rules;
    size_t           nrules;
    size_t           nstates;
    int32_t        (*next)[256];   /* state x byte -> state (full DFA) */
    int32_t         *fail;
    int32_t         *head;         /* first rule ending at this state, -1 = none */
    int32_t         *link;         /* nearest state on the fail chain (or self) that ends a rule */
    int32_t         *rule_next;    /* next rule ending at the same state */
    uint64_t        *rule_seen;    /* scan number of the rule's last hit */
    uint64_t         scans;
};

/* Literal bytes, plus Snort-style |hex| blocks for binary: |0d 0a| = CRLF. */
static int parse_content(const char *s, struct sig_rule *r)
{
    int hex = 0;
    r->len = 0;
    while (*s) {
        unsigned v;
        if (*s == '|') {
            hex = !hex;
            s++;
            continue;
        }
        if (hex && *s == ' ') {
            s++;
            continue;
        }
        if (hex) {
            if (!isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1]))
                return -1;
            sscanf(s, "%2x", &v);
            s += 2;
        } else {
            v = (unsigned char)*s++;
        }
        if (r->len == SIG_CONTENT_MAX)
            return -1;
        r->content[r->len++] = (uint8_t)v;
    }
    return (hex || r->len == 0) ? -1 : 0;
}

/* One rule per line:  <sid>  "<message>"  <content> */
static int load_rules(const char *path, struct sig_matcher *m)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "error: could not open rules '%s'\n", path);
        return -1;
    }

    char line[1024];
    size_t cap = 0;
    int lineno = 0, rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        lineno++;
        size_t n = strcspn(line, "\n");
        if (line[n] != '\n' && !feof(f)) {
            fprintf(stderr, "error: %s:%d: line too long\n", path, lineno);
            rc = -1;
            break;
        }
        while (n > 0 && isspace((unsigned char)line[n - 1]))
            n--;
        line[n] = '\0';

        const char *p = line;
        while (isspace((unsigned char)*p))
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        if (m->nrules == cap) {
            cap = cap ? cap * 2 : 64;
            struct sig_rule *grown = realloc(m->rules, cap * sizeof *grown);
            if (grown == NULL) {
                fprintf(stderr, "error: out of memory loading rules\n");
                rc = -1;
                break;
            }
            m->rules = grown;
        }

        struct sig_rule *r = &m->rules[m->nrules];
        int off = -1;
        if (sscanf(p, "%u \"%127[^\"]\" %n", &r->sid, r->msg, &off) != 2 || off < 0 ||
            parse_content(p + off, r) < 0) {
            fprintf(stderr, "error: %s:%d: bad rule\n", path, lineno);
            rc = -1;
            break;
        }
        m->nrules++;
    }
    fclose(f);
    return rc;
}

static int build(struct sig_matcher *m)
{
    /* Dense 256-wide rows: ~1 KB per state. Fine for thousands of rules;
       a sparse layout would be needed for Snort-sized rule sets. */
    size_t max = 1;
    for (size_t i = 0; i < m->nrules; i++)
        max += m->rules[i].len;

    m->next      = malloc(max * sizeof *m->next);
    m->fail      = calloc(max, sizeof *m->fail);
    m->head      = malloc(max * sizeof *m->head);
    m->link      = calloc(max, sizeof *m->link);
    m->rule_next = malloc((m->nrules + 1) * sizeof *m->rule_next);
    m->rule_seen = calloc(m->nrules + 1, sizeof *m->rule_seen);
    int32_t *queue = malloc(max * sizeof *queue);
    if (!m->next || !m->fail || !m->head || !m->link || !m->rule_next || !m->rule_seen || !queue) {
        free(queue);
        fprintf(stderr, "error: out of memory building matcher\n");
        return -1;
    }
    memset(m->next, 0xff, max * sizeof *m->next);   /* -1 = no edge yet */
    memset(m->head, 0xff, max * sizeof *m->head);

    /* 1. trie of all rule contents */
    m->nstates = 1;
    for (size_t i = 0; i < m->nrules; i++) {
        int32_t s = 0;
        for (size_t j = 0; j < m->rules[i].len; j++) {
            uint8_t c = m->rules[i].content[j];
            if (m->next[s][c] < 0)
                m->next[s][c] = (int32_t)m->nstates++;
            s = m->next[s][c];
        }
        m->rule_next[i] = m->head[s];
        m->head[s] = (int32_t)i;
    }

    /* 2. breadth-first: fail links, then fill missing edges from the fail state */
    size_t qh = 0, qt = 0;
    queue[qt++] = 0;
    while (qh < qt) {
        int32_t u = queue[qh++];
        for (int c = 0; c < 256; c++) {
            int32_t v = m->next[u][c];
            int32_t f = u ? m->next[m->fail[u]][c] : 0;
            if (v < 0) {
                m->next[u][c] = f;
                continue;
            }
            m->fail[v] = f;
            m->link[v] = m->head[v] >= 0 ? v : m->link[f];
            queue[qt++] = v;
        }
    }
    free(queue);
    return 0;
}

struct sig_matcher *sig_load(const char *path)
{
    struct sig_matcher *m = calloc(1, sizeof *m);
    if (m == NULL)
        return NULL;
    if (load_rules(path, m) < 0 || build(m) < 0) {
        sig_free(m);
        return NULL;
    }
    return m;
}

void sig_scan(struct sig_matcher *m, const uint8_t *data, size_t len,
              sig_hit_fn hit, void *ctx)
{
    uint64_t scan = ++m->scans;
    int32_t s = 0;
    for (size_t i = 0; i < len; i++) {
        s = m->next[s][data[i]];
        for (int32_t t = m->link[s]; t; t = m->link[m->fail[t]]) {
            for (int32_t r = m->head[t]; r >= 0; r = m->rule_next[r]) {
                if (m->rule_seen[r] == scan)
                    continue;               /* one alert per rule per payload */
                m->rule_seen[r] = scan;
                hit(&m->rules[r], i + 1 - m->rules[r].len, ctx);
            }
        }
    }
}

void sig_free(struct sig_matcher *m)
{
    if (m == NULL)
        return;
    free(m->rules);
    free(m->next);
    free(m->fail);
    free(m->head);
    free(m->link);
    free(m->rule_next);
    free(m->rule_seen);
    free(m);
}
