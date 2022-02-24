#include "iwre.h"
#include "cregex.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct iwre {
  cregex_program_t *program;
};

int iwre_match(struct iwre *re, const char *text, const char *mpairs[], size_t mpairs_len) {
  if (mpairs_len % 2 != 0) {
    errno = EINVAL;
    return -1;
  }
  memset(mpairs, 0, sizeof(mpairs[0]) * mpairs_len);
  int ret = cregex_program_run(re->program, text, mpairs, mpairs_len);
  if (ret < 1) {
    return 0;
  }
  for (int i = 0, ret = 0; i < mpairs_len && mpairs[i]; ++i) {
    ++ret;
  }
  return ret / 2;
}

void iwre_destroy(struct iwre *re) {
  if (re) {
    cregex_compile_free(re->program);
    free(re);
  }
}

struct iwre* iwre_create(const char *pattern) {
  struct iwre *re = calloc(1, sizeof(*re));
  if (!re) {
    return 0;
  }
  cregex_node_t *node = cregex_parse(pattern);
  if (!node) {
    goto error;
  }
  re->program = cregex_compile_node(node);
  if (!re->program) {
    goto error;
  }
  cregex_parse_free(node);
  return re;

error:
  if (node) {
    cregex_parse_free(node);
  }
  iwre_destroy(re);
  return 0;
}
