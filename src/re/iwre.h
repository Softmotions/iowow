#pragma once

#ifndef IW_IWRE_H
#define IW_IWRE_H

#include "basedefs.h"

#define IWRE_MAX_MATCHES 64

struct iwre;

struct iwre* iwre_create(const char *pattern);

/// @return Number of of matches `n`, where `2*n <= nmatches`
int iwre_match(struct iwre*, const char *text, const char *mpairs[], size_t mpairs_len);

void iwre_destroy(struct iwre*);

#endif
