/*
Copyright (c) 2011, Willem-Hendrik Thiart
Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * The names of its contributors may not be used to endorse or promote
      products derived from this software without specific prior written
      permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL WILLEM-HENDRIK THIART BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "iwstree.h"
#include "iwlog.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>

typedef struct tree_node_s {
  struct tree_node_s  *left;
  struct tree_node_s  *right;
  void *key;
  void *value;
} tree_node_t;


struct tree_iter_s {
  IWSTREE *st;        /**< Owner tree */
  int spos;           /**< Position of top element stack */
  int slen;           /**< Max number of elements in stack */
  tree_node_t **stack; /**< Bottom of iterator stack */
};

int iwstree_str_cmp(const void *o1, const void *o2) {
  return strcmp(o1, o2);
}

int iwstree_uint64_cmp(const void *o1, const void *o2) {
  uint64_t v1 = *(uint64_t *) o1;
  uint64_t v2 = *(uint64_t *) o2;
  return v1 > v2 ? 1 : v1 < v2 ? -1 : 0;
}

int iwstree_int64_cmp(const void *o1, const void *o2) {
  int64_t v1 = *(int64_t *) o1;
  int64_t v2 = *(int64_t *) o2;
  return v1 > v2 ? 1 : v1 < v2 ? -1 : 0;
}

static int _cmp_default(const void *k1, const void *k2) {
  return k1 < k2 ? -1 : k1 > k2 ? 1 : 0;
}

IWSTREE *iwstree_create(int (*cmp)(const void *, const void *),
                        void (*kvfree)(void *, void *)) {
  IWSTREE *st;
  st = malloc(sizeof(IWSTREE));
  if (!st) {
    return 0;
  }
  memset(st, 0, sizeof(IWSTREE));
  if (!cmp) {
    cmp = _cmp_default;
  }
  st->cmp = cmp;
  st->kvfree = kvfree;
  return st;
}

static void _free_node(IWSTREE *st, tree_node_t *node) {
  if (node) {
    _free_node(st, node->left);
    _free_node(st, node->right);
    if (st->kvfree) {
      st->kvfree(node->key, node->value);
    }
    free(node);
  }
}

void iwstree_clear(IWSTREE *st) {
  if (st) {
    _free_node(st, st->root);
    st->root = 0;
  }
}

void iwstree_destroy(IWSTREE *st) {
  iwstree_clear(st);
  free(st);
}

static tree_node_t *_init_node(void *key, void *value) {
  tree_node_t *n;
  n = malloc(sizeof(tree_node_t));
  if (!n) {
    return 0;
  }
  n->left = n->right = 0;
  n->key = key;
  n->value = value;
  return n;
}

static void _rotate_right(tree_node_t **pa) {
  tree_node_t *child;
  child = (*pa)->left;
  assert(child);
  (*pa)->left = child->right;
  child->right = *pa;
  *pa = child;
}

static void _rotate_left(tree_node_t **pa) {
  tree_node_t *child;
  child = (*pa)->right;
  assert(child);
  (*pa)->right = child->left;
  child->left = *pa;
  *pa = child;
}

/**
 * bring this value to the top
 * */
static tree_node_t *_splay(
  IWSTREE *st,
  int update_if_not_found,
  tree_node_t **gpa,
  tree_node_t **pa,
  tree_node_t **child,
  const void *key) {

  int cmp;
  tree_node_t *next;

  if (!(*child)) {
    return 0;
  }
  cmp = st->cmp((*child)->key, key);
  if (cmp == 0) {
    next = *child;
  } else if (cmp > 0) {
    next = _splay(st, update_if_not_found, pa, child, &(*child)->left, key);
  } else {
    next = _splay(st, update_if_not_found, pa, child, &(*child)->right, key);
  }
  if (!next) {
    if (update_if_not_found) {
      next = *child;
    } else {
      return 0;
    }
  } else {
    if (next != *child) {
      return next;
    }
  }

  if (!pa) {
    return next;
  }

  if (!gpa) {
    /* zig left */
    if ((*pa)->left == next) {
      _rotate_right(pa);
    }
    /* zig right */
    else {
      _rotate_left(pa);
    }
    return next;
  }

  assert(gpa);

  /* zig zig left */
  if ((*pa)->left == next && (*gpa)->left == *pa) {
    _rotate_right(pa);
    _rotate_right(gpa);
  }
  /* zig zig right */
  else if ((*pa)->right == next && (*gpa)->right == *pa) {
    _rotate_left(pa);
    _rotate_left(gpa);
  }
  /* zig zag right */
  else if ((*pa)->right == next && (*gpa)->left == *pa) {
    _rotate_left(pa);
    _rotate_right(gpa);
  }
  /* zig zag left */
  else if ((*pa)->left == next && (*gpa)->right == *pa) {
    _rotate_right(pa);
    _rotate_left(gpa);
  }
  return next;
}

int iwstree_is_empty(IWSTREE *st) {
  return st->root == 0;
}

void *iwstree_remove(IWSTREE *st, const void *key) {
  tree_node_t *root, *tmp;
  void *val;

  /*  make removed node the root */
  if (!iwstree_get(st, key)) {
    return 0;
  }
  root = st->root;
  val = root->value;

  assert(0 < st->count);
  if (root->left == 0) {
    st->root = root->right;
  } else {
    tmp = root->right;
    st->root = root->left;
    _splay(st, 1, 0, 0, (tree_node_t **) &st->root, key);
    ((tree_node_t *) st->root)->right = tmp;
  }
  st->count--;
  assert(root != st->root);
  free(root);
  return val;
}

/**
 * get this item referred to by key. Slap it as root.
 */
void *iwstree_get(IWSTREE *st, const void *key) {
  tree_node_t *node = _splay(st, 0, 0, 0, (tree_node_t **) &st->root, key);
  return node ? node->value : 0;
}

int iwstree_count(IWSTREE *st) {
  return st->count;
}

void *iwstree_peek(IWSTREE *st) {
  return st->root ? ((tree_node_t *) st->root)->value : 0;
}

static iwrc _iwstree_put(IWSTREE *st, void *key, void *value, bool overwrite) {
  tree_node_t *n;
  int cmp;
  if (!st->root) {
    st->root = _init_node(key, value);
    if (!st->root) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    st->count++;
    return 0;
  }
  n = _splay(st, 1, 0, 0, (tree_node_t **) &st->root, key);
  cmp = st->cmp(((tree_node_t *) st->root)->key, key);
  if (cmp != 0) {
    n = _init_node(key, value);
    if (!n) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    if (0 < cmp) {
      n->right = st->root;
      n->left = n->right->left;
      n->right->left = 0;
    } else {
      n->left = st->root;
      n->right = n->left->right;
      n->left->right = 0;
    }
    st->count++;
  } else if (overwrite) {
    if (n->value && st->kvfree) {
      st->kvfree(0, n->value);
    }
    n->value = value;
  }
  st->root = n;
  return 0;
}

iwrc iwstree_put(IWSTREE *st, void *key, void *value) {
  return _iwstree_put(st, key, value, false);
}

iwrc iwstree_put_overwrite(IWSTREE *st, void *key, void *value) {
  return _iwstree_put(st, key, value, true);
}

static iwrc _iwstree_visit(tree_node_t *n, IWSTREE_VISITOR visitor, void *op) {
  iwrc rc = 0;
  if (!visitor(n->key, n->value, op, &rc) || rc) {
    return rc;
  }
  if (n->left) {
    rc = _iwstree_visit(n->left, visitor, op);
    RCRET(rc);
  }
  if (n->right) {
    rc = _iwstree_visit(n->right, visitor, op);
    RCRET(rc);
  }
  return rc;
}

iwrc iwstree_visit(IWSTREE *st, IWSTREE_VISITOR visitor, void *op) {
  if (st->root) {
    return _iwstree_visit(st->root, visitor, op);
  }
  return 0;
}

#define _ITER_STACK_AUNIT 32

static iwrc _iter_push(IWSTREE_ITER *iter, tree_node_t *n)  {
  if (iter->spos + 1 > iter->slen) {
    void *np = realloc(iter->stack, (iter->slen + _ITER_STACK_AUNIT) * sizeof(*iter->stack));
    if (!np) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    iter->stack = np;
    iter->slen += _ITER_STACK_AUNIT;
  }
  iter->stack[iter->spos] = n;
  iter->spos++;
  return 0;
}

static tree_node_t *_iter_pop(IWSTREE_ITER *iter) {
  if (iter->spos < 1) {
    return 0;
  }
  iter->spos--;
  return iter->stack[iter->spos];
}

iwrc iwstree_iter_init(IWSTREE *st, IWSTREE_ITER *iter) {
  memset(iter, 0, sizeof(*iter));
  iter->st = st;
  tree_node_t *n = st->root;
  while (n) {
    iwrc rc = _iter_push(iter, n);
    RCRET(rc);
    n = n->left;
  }
  return 0;
}

bool iwstree_iter_has_next(IWSTREE_ITER *iter) {
  return iter->spos > 0;
}

iwrc iwstree_iter_next(IWSTREE_ITER *iter, void **key, void **val) {
  if (key) {
    *key = 0;
  }
  if (val) {
    *val = 0;
  }
  if (iter->spos < 1) {
    return IW_ERROR_NOT_EXISTS;
  }
  tree_node_t *n = _iter_pop(iter);
  assert(n);
  if (key) {
    *key = n->key;
  }
  if (val) {
    *val = n->value;
  }
  if (n->right) {
    n = n->right;
    while (n) {
      iwrc rc = _iter_push(iter, n);
      RCRET(rc);
      n = n->left;
    }
  }
  return 0;
}

void iwstree_iter_close(IWSTREE_ITER *iter) {
  if (iter->stack) {
    free(iter->stack);
  }
  iter->slen = 0;
  iter->spos = 0;
  iter->stack = 0;
}
