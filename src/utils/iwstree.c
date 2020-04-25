/*
Copyright (c) 2011, Willem-Hendrik Thiart
Copyright (c) 2012-2020 Softmotions Ltd <info@softmotions.com>
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

typedef struct _tree_node_t {
  struct _tree_node_t  *left;
  struct _tree_node_t  *right;
  void *key;
  void *value;
} tree_node_t;

int iwstree_str_cmp(const void *o1, const void *o2) {
  return strcmp(o1, o2);
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

void iwstree_destroy(IWSTREE *st) {
  _free_node(st, st->root);
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
    if (next != *child)
      return next;
  }

  if (!pa)
    return next;

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
  tree_node_t *root, *left_highest;
  void *val;

  /*  make removed node the root */
  if (!iwstree_get(st, key)) {
    return 0;
  }
  root = st->root;
  val = root->value;

  assert(0 < st->count);
  assert(root->key == key);

  /* get left side's most higest value node */
  if ((left_highest = root->left)) {
    tree_node_t *prev = root;
    while (left_highest->right) {
      prev = left_highest;
      left_highest = left_highest->right;
    }
    /* do the swap */
    prev->right = 0;
    st->root = left_highest;
    left_highest->left = root->left;
    left_highest->right = root->right;
  } else {
    assert(root);
    st->root = root->right;
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
  tree_node_t *node;
  node = _splay(st, 0, 0, 0, (tree_node_t **) &st->root, key);
  return node ? node->value : 0;
}

int iwstree_count(IWSTREE *st) {
  return st->count;
}

void *iwstree_peek(IWSTREE *st) {
  return st->root ? ((tree_node_t *) st->root)->value : 0;
}

iwrc iwstree_put(IWSTREE *st, void *key, void *value) {
  tree_node_t *n;
  int cmp;
  if (!st->root) {
    st->root = _init_node(key, value);
    if (!st->root) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    st->count++;
    goto exit;
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
  }
  st->root = n;

exit:
  return 0;
}

static void _iwstree_visit(tree_node_t *n, int (*visitor)(const void *, const void *)) {
  if (!visitor(n->key, n->value)) {
    return;
  }
  if (n->left) {
    _iwstree_visit(n->left, visitor);
  }
  if (n->right) {
    _iwstree_visit(n->right, visitor);
  }
}

void iwstree_visit(IWSTREE *st, int (*visitor)(const void *, const void *)) {
  if (st->root) {
    _iwstree_visit(st->root, visitor);
  }
}
