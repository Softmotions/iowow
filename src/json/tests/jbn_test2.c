// JSON pointers, JSON Patch and JSON Merge Patch tests for the DOM tree API.
#include "iwlog.h"
#include "iwxstr.h"
#include "iwutils.h"
#include "iwpool.h"

#include "iwjson.h"

#include <stdlib.h>
#include <string.h>
#include "tests.h"

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

static struct jbl_node* from_json(struct iwpool *pool, const char *json) {
  struct jbl_node *n = 0;
  iwrc rc = jbn_from_json(json, &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(n);
  return n;
}

/** Releases a tree allocated without a memory pool. */
static iwrc _free_node(int lvl, struct jbl_node *n) {
  free((void*) n->key);
  if (n->type == JBV_STR) {
    free((void*) n->vptr);
  }
  free(n);
  return 0;
}

static void assert_as_json(struct jbl_node *node, const char *expected) {
  char *out = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json_alloc(node, 0, &out), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(out);
  IW_TEST_ASSERT_STR_EQUAL(out, expected);
  free(out);
}

/** Applies the JSON Patch document `patchjson` to `root`. */
static void apply_patch(struct jbl_node *root, const char *patchjson, struct iwpool *pool) {
  struct jbl_node *patch = from_json(pool, patchjson);
  iwrc rc = jbn_patch_auto(root, patch, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

//--- JSON pointer

static void jbn_test2_ptr(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct iwxstr *xstr = iwxstr_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(xstr);

  struct jbl_ptr *p1 = 0, *p2 = 0;

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("/a~0b/c~1d/0", &p1, pool), 0);
  IW_TEST_ASSERT_EQUAL(p1->cnt, 3);
  IW_TEST_ASSERT_STR_EQUAL(p1->n[0], "a~b");
  IW_TEST_ASSERT_STR_EQUAL(p1->n[1], "c/d");
  IW_TEST_ASSERT_STR_EQUAL(p1->n[2], "0");

  // Serialization must escape `~` and `/` back
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_serialize(p1, xstr), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "/a~0b/c~1d/0");

  // The serialized pointer parses to an equal pointer
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool(iwxstr_ptr(xstr), &p2, pool), 0);
  IW_TEST_ASSERT_EQUAL(jbl_ptr_cmp(p1, p2), 0);

  // Empty pointer
  iwxstr_clear(xstr);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("", &p2, pool), 0);
  IW_TEST_ASSERT_EQUAL(p2->cnt, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_serialize(p2, xstr), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "");

  // Comparison by path nodes
  struct jbl_ptr *pa = 0, *pb = 0, *pab = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("/a", &pa, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("/b", &pb, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("/a/b", &pab, pool), 0);

  IW_TEST_ASSERT_TRUE(jbl_ptr_cmp(pa, pb) < 0);
  IW_TEST_ASSERT_TRUE(jbl_ptr_cmp(pb, pa) > 0);
  IW_TEST_ASSERT_EQUAL(jbl_ptr_cmp(pa, pa), 0);

  // A common prefix: the shorter path is lesser
  IW_TEST_ASSERT_TRUE(jbl_ptr_cmp(pa, pab) < 0);
  IW_TEST_ASSERT_TRUE(jbl_ptr_cmp(pab, pa) > 0);

  // Node wise comparison is independent of the raw path length
  IW_TEST_ASSERT_TRUE(jbl_ptr_cmp(pb, pab) > 0);

  // Out of pool allocation
  struct jbl_ptr *hp = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc("/x~1y", &hp), 0);
  iwxstr_clear(xstr);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_serialize(hp, xstr), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "/x~1y");
  free(hp);

  IW_TEST_ASSERT_EQUAL(jbl_ptr_alloc("/x~2y", &hp), JBL_ERROR_JSON_POINTER);
  IW_TEST_ASSERT_EQUAL(jbl_ptr_alloc("/x/", &hp), JBL_ERROR_JSON_POINTER);

  iwxstr_destroy(xstr);
  iwpool_destroy(pool);
}

//--- JSON Patch

static void _patch_basic(struct jbl_node *root, struct iwpool *pool) {
  // Add, replace, remove, move, test, copy, increment, swap
  apply_patch(root, "["
              "{\"op\":\"add\",\"path\":\"/added\",\"value\":{\"k\":[1,2]}},"
              "{\"op\":\"replace\",\"path\":\"/n\",\"value\":10},"
              "{\"op\":\"remove\",\"path\":\"/removed\"},"
              "{\"op\":\"move\",\"from\":\"/src\",\"path\":\"/dst\"}"
              "]", pool);
  assert_as_json(root, "{\"arr\":[1,2],\"added\":{\"k\":[1,2]},\"n\":10,\"dst\":{\"v\":1}}");

  // Add into an array at the beginning/middle/end
  apply_patch(root, "[{\"op\":\"add\",\"path\":\"/arr/0\",\"value\":0}]", pool);
  apply_patch(root, "[{\"op\":\"add\",\"path\":\"/arr/2\",\"value\":9}]", pool);
  apply_patch(root, "[{\"op\":\"add\",\"path\":\"/arr/-\",\"value\":7}]", pool);
  assert_as_json(root, "{\"arr\":[0,1,9,2,7],\"added\":{\"k\":[1,2]},\"n\":10,\"dst\":{\"v\":1}}");

  // Increment
  apply_patch(root, "[{\"op\":\"increment\",\"path\":\"/n\",\"value\":5}]", pool);
  assert_as_json(root, "{\"arr\":[0,1,9,2,7],\"added\":{\"k\":[1,2]},\"n\":15,\"dst\":{\"v\":1}}");

  // Add with creation of intermediate objects
  apply_patch(root, "[{\"op\":\"add_create\",\"path\":\"/x/y/z\",\"value\":true}]", pool);
  iwrc rc = 0;
  struct jbl_node *v;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/x/y/z", &v), 0);
  IW_TEST_ASSERT_EQUAL(v->type, JBV_BOOL);
  IW_TEST_ASSERT_EQUAL(v->vbool, true);

  // Test operation
  apply_patch(root, "[{\"op\":\"test\",\"path\":\"/n\",\"value\":15}]", pool);

  // An empty patch document is a no-op
  apply_patch(root, "[]", pool);
  assert_as_json(root,
                 "{\"arr\":[0,1,9,2,7],\"added\":{\"k\":[1,2]},\"n\":15,\"dst\":{\"v\":1},"
                 "\"x\":{\"y\":{\"z\":true}}}");
}

static void jbn_test2_patch(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct jbl_node *root = from_json(
    pool, "{\"n\":1,\"removed\":true,\"src\":{\"v\":1},\"arr\":[1,2]}");
  _patch_basic(root, pool);
  iwpool_destroy(pool);
}

static void jbn_test2_patch_copy(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"foo\":{\"bar\":1},\"arr\":[1,2]}");

  // Copy into a new object member
  apply_patch(root, "[{\"op\":\"copy\",\"from\":\"/foo\",\"path\":\"/baz\"}]", pool);
  assert_as_json(root, "{\"foo\":{\"bar\":1},\"arr\":[1,2],\"baz\":{\"bar\":1}}");

  // The copy is independent of the source
  apply_patch(root, "[{\"op\":\"replace\",\"path\":\"/baz/bar\",\"value\":2}]", pool);
  assert_as_json(root, "{\"foo\":{\"bar\":1},\"arr\":[1,2],\"baz\":{\"bar\":2}}");

  // Copy over an existing target
  apply_patch(root, "[{\"op\":\"copy\",\"from\":\"/foo\",\"path\":\"/baz\"}]", pool);
  assert_as_json(root, "{\"foo\":{\"bar\":1},\"arr\":[1,2],\"baz\":{\"bar\":1}}");
  apply_patch(root, "[{\"op\":\"replace\",\"path\":\"/baz/bar\",\"value\":3}]", pool);
  assert_as_json(root, "{\"foo\":{\"bar\":1},\"arr\":[1,2],\"baz\":{\"bar\":3}}");

  // Copy an array element to the end of the same array
  apply_patch(root, "[{\"op\":\"copy\",\"from\":\"/arr/0\",\"path\":\"/arr/-\"}]", pool);
  assert_as_json(root, "{\"foo\":{\"bar\":1},\"arr\":[1,2,1],\"baz\":{\"bar\":3}}");

  // Copy a scalar to an explicit array position
  apply_patch(root, "[{\"op\":\"copy\",\"from\":\"/baz/bar\",\"path\":\"/arr/1\"}]", pool);
  assert_as_json(root, "{\"foo\":{\"bar\":1},\"arr\":[1,3,2,1],\"baz\":{\"bar\":3}}");

  // The source path of a copy must exist
  struct jbl_node *patch = from_json(pool, "[{\"op\":\"copy\",\"from\":\"/zzz\",\"path\":\"/q\"}]");
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, patch, pool), JBL_ERROR_PATH_NOTFOUND);

  iwpool_destroy(pool);
}

static void jbn_test2_patch_errors(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"a\":{\"b\":1},\"arr\":[1]}");
  iwrc rc;

  // Invalid pointer path
  struct jbl_patch pptr[] = { { .op = JBP_ADD, .path = "bad", .vjson = "1" } };
  struct jbl_node *vnode = from_json(pool, "1");
  pptr[0].vnode = vnode;
  rc = jbn_patch(root, pptr, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_JSON_POINTER);

  // Missing value
  struct jbl_patch pnoval[] = { { .op = JBP_ADD, .path = "/x" } };
  rc = jbn_patch(root, pnoval, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATCH_NOVALUE);

  struct jbl_patch ptestnoval[] = { { .op = JBP_TEST, .path = "/a/b" } };
  rc = jbn_patch(root, ptestnoval, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATCH_NOVALUE);

  // Failed test operation
  struct jbl_patch ptest[] = { { .op = JBP_TEST, .path = "/a/b", .vnode = vnode } };
  struct jbl_node *two = from_json(pool, "2");
  ptest[0].vnode = two;
  rc = jbn_patch(root, ptest, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATCH_TEST_FAILED);

  // Invalid array index
  struct jbl_node *four = from_json(pool, "4");
  struct jbl_patch pidx[] = { { .op = JBP_ADD, .path = "/arr/5", .vnode = four } };
  rc = jbn_patch(root, pidx, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATCH_INVALID_ARRAY_INDEX);

  // Missing parent of the target path
  struct jbl_patch ptarget[] = { { .op = JBP_ADD, .path = "/zzz/xxx", .vnode = four } };
  rc = jbn_patch(root, ptarget, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATCH_TARGET_INVALID);

  // Increment of a non numeric value
  struct jbl_node *num = from_json(pool, "1");
  struct jbl_patch pinc[] = { { .op = JBP_INCREMENT, .path = "/zzz", .vnode = num } };
  rc = jbn_patch(root, pinc, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATCH_TARGET_INVALID);

  struct jbl_node *str = from_json(pool, "\"s\"");
  struct jbl_patch pinc2[] = { { .op = JBP_INCREMENT, .path = "/a/b", .vnode = str } };
  rc = jbn_patch(root, pinc2, 1, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATCH_INVALID_VALUE);

  // Invalid arguments
  IW_TEST_ASSERT_EQUAL(jbn_patch(root, pinc2, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL(jbn_patch(0, pinc2, 1, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_patch(root, 0, 1, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(0, root, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, 0, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, root, 0), IW_ERROR_INVALID_ARGS);

  struct jbl_node *nopatch = from_json(pool, "\"str\"");
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, nopatch, pool), IW_ERROR_INVALID_ARGS);

  // Invalid patch documents
  struct jbl_node *badop = from_json(pool, "[{\"op\":\"zzz\",\"path\":\"/x\",\"value\":1}]");
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, badop, pool), JBL_ERROR_PATCH_INVALID_OP);

  struct jbl_node *badpath = from_json(pool, "[{\"op\":\"add\",\"path\":1,\"value\":1}]");
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, badpath, pool), JBL_ERROR_PATCH_INVALID);

  struct jbl_node *notobj = from_json(pool, "[1]");
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, notobj, pool), JBL_ERROR_PATCH_INVALID);

  struct jbl_node *badoptype = from_json(pool, "[{\"op\":1,\"path\":\"/x\",\"value\":1}]");
  IW_TEST_ASSERT_EQUAL(jbn_patch_auto(root, badoptype, pool), JBL_ERROR_PATCH_INVALID);

  iwpool_destroy(pool);
}

//--- JSON Merge Patch

static void jbn_test2_merge_patch(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"a\":{\"b\":1,\"c\":2},\"d\":[1,2],\"e\":\"s\"}");

  struct jbl_node *patch = from_json(pool, "{\"a\":{\"b\":3,\"c\":null},\"d\":[3],\"e\":{\"f\":1}}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch(root, patch, pool), 0);
  assert_as_json(root, "{\"a\":{\"b\":3},\"d\":[3],\"e\":{\"f\":1}}");

  // A null merge patch removes the value
  struct jbl_node *nullpatch = from_json(pool, "{\"a\":null}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch(root, nullpatch, pool), 0);
  assert_as_json(root, "{\"d\":[3],\"e\":{\"f\":1}}");

  // Merge patch requires an object root
  struct jbl_node *arr = from_json(pool, "[]");
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch(arr, patch, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch(0, patch, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch(root, 0, pool), IW_ERROR_INVALID_ARGS);

  // Merge patch from JSON text: root replacement by a non object value
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_from_json(root, "[1,2]", pool), 0);
  assert_as_json(root, "[1,2]");

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_from_json(root, "{\"a\":1}", pool), 0);
  assert_as_json(root, "{\"a\":1}");

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_from_json(root, "\"str\"", pool), 0);
  assert_as_json(root, "\"str\"");

  // Invalid JSON is reported
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch_from_json(root, "{", pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch_from_json(0, "{}", pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch_from_json(root, 0, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch_from_json(root, "{}", 0), IW_ERROR_INVALID_ARGS);

  iwpool_destroy(pool);
}

static void jbn_test2_merge_patch_create(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *val = from_json(pool, "1");
  struct jbl_node *out = 0;

  // The value is nested under the path
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_create("/a/b/c", val, pool, &out), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(out);
  assert_as_json(out, "{\"a\":{\"b\":{\"c\":1}}}");

  // Root paths return the value as is
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_create("", val, pool, &out), 0);
  IW_TEST_ASSERT_EQUAL(out, val);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_create("/", val, pool, &out), 0);
  IW_TEST_ASSERT_EQUAL(out, val);

  // A missing value produces an empty object chain
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_create("/x/y", 0, pool, &out), 0);
  assert_as_json(out, "{\"x\":{\"y\":{}}}");

  // Invalid path
  IW_TEST_ASSERT_EQUAL(jbn_merge_patch_create("x", val, pool, &out), JBL_ERROR_JSON_POINTER);

  // Merge the created tree into an existing tree
  struct jbl_node *root = from_json(pool, "{\"a\":{\"bb\":1}}");
  struct jbl_node *v2 = from_json(pool, "2");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_path(root, "/a/c", v2, pool), 0);
  assert_as_json(root, "{\"a\":{\"bb\":1,\"c\":2}}");

  // A null value removes the value at the path
  struct jbl_node nullval = { .type = JBV_NULL };
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_path(root, "/a/bb", &nullval, pool), 0);
  assert_as_json(root, "{\"a\":{\"c\":2}}");

  // No pool: the merged nodes are allocated with malloc() and belong to the target tree
  struct jbl_node *mroot = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("{\"a\":{\"c\":2}}", &mroot, 0), 0);
  struct jbl_node v3 = { .type = JBV_I64, .vi64 = 3 };
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_merge_patch_path(mroot, "/a/d", &v3, 0), 0);
  assert_as_json(mroot, "{\"a\":{\"c\":2,\"d\":3}}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_visit2(mroot, 0, _free_node), 0);

  iwpool_destroy(pool);
}

//--- jbn_copy_path

static void jbn_test2_copy_path(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *src = from_json(pool, "{\"a\":{\"b\":1},\"nul\":null,\"arr\":[1,2]}");
  struct jbl_node *tgt = from_json(pool, "{\"t\":{\"keep\":1}}");

  // Copy a subtree
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_path(src, "/a", tgt, "/t/a", false, false, pool), 0);
  assert_as_json(tgt, "{\"t\":{\"keep\":1,\"a\":{\"b\":1}}}");

  // Null values are not copied by default
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_path(src, "/nul", tgt, "/t/nul", false, false, pool), 0);
  assert_as_json(tgt, "{\"t\":{\"keep\":1,\"a\":{\"b\":1}}}");

  // ... but are copied on demand
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_path(src, "/nul", tgt, "/t/nul", true, false, pool), 0);
  assert_as_json(tgt, "{\"t\":{\"keep\":1,\"a\":{\"b\":1},\"nul\":null}}");

  // A missing source path is a no-op
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_path(src, "/zzz", tgt, "/t/zzz", true, false, pool), 0);
  assert_as_json(tgt, "{\"t\":{\"keep\":1,\"a\":{\"b\":1},\"nul\":null}}");

  // A missing target path is created
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_path(src, "/arr/1", tgt, "/q/w/e", false, false, pool), 0);
  assert_as_json(tgt, "{\"t\":{\"keep\":1,\"a\":{\"b\":1},\"nul\":null},\"q\":{\"w\":{\"e\":2}}}");

  // The whole source document
  struct jbl_node *tgt2 = from_json(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_path(src, "/", tgt2, "/all", false, false, pool), 0);
  assert_as_json(tgt2, "{\"all\":{\"a\":{\"b\":1},\"nul\":null,\"arr\":[1,2]}}");

  // No source clone: the source subtree is moved into the target tree
  struct jbl_node *nsrc = from_json(pool, "{\"x\":{\"y\":9}}");
  struct jbl_node *nod = from_json(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_path(nsrc, "/x", nod, "/z", false, true, pool), 0);
  assert_as_json(nod, "{\"z\":{\"y\":9}}");
  assert_as_json(nsrc, "{}");

  // Path list copy
  const char *paths[] = { "/a/b", "/arr/0", 0 };
  struct jbl_node *tgt3 = from_json(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_copy_paths(src, tgt3, paths, false, false, pool), 0);
  assert_as_json(tgt3, "{\"a\":{\"b\":1},\"arr\":[1]}");

  // Invalid arguments
  IW_TEST_ASSERT_EQUAL(jbn_copy_path(0, "/a", tgt, "/a", false, false, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_copy_path(src, 0, tgt, "/a", false, false, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_copy_path(src, "/a", 0, "/a", false, false, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_copy_path(src, "/a", tgt, 0, false, false, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_copy_path(src, "/a", tgt, "/a", false, false, 0), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_copy_paths(src, tgt, 0, false, false, pool), IW_ERROR_INVALID_ARGS);
  const char *badpath[] = { "bad", 0 };
  IW_TEST_ASSERT_EQUAL(jbn_copy_paths(src, tgt, badpath, false, false, pool),
                       JBL_ERROR_JSON_POINTER);

  iwpool_destroy(pool);
}

static void jbn_test2_patch_auto_merge(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"a\":{\"b\":1},\"arr\":[1,2]}");

  // An object patch document is applied as a merge patch
  struct jbl_node *merge = from_json(pool, "{\"a\":{\"c\":2}}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_patch_auto(root, merge, pool), 0);
  assert_as_json(root, "{\"a\":{\"b\":1,\"c\":2},\"arr\":[1,2]}");

  // Repeated application works with a fresh patch tree
  struct jbl_node *merge2 = from_json(pool, "{\"a\":{\"d\":3}}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_patch_auto(root, merge2, pool), 0);
  assert_as_json(root, "{\"a\":{\"b\":1,\"c\":2,\"d\":3},\"arr\":[1,2]}");

  iwpool_destroy(pool);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(jbn_test2_ptr),
  IW_TEST_CASE(jbn_test2_patch),
  IW_TEST_CASE(jbn_test2_patch_copy),
  IW_TEST_CASE(jbn_test2_patch_errors),
  IW_TEST_CASE(jbn_test2_merge_patch),
  IW_TEST_CASE(jbn_test2_merge_patch_create),
  IW_TEST_CASE(jbn_test2_copy_path),
  IW_TEST_CASE(jbn_test2_patch_auto_merge),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("jbn_test2", cases, init_suite, 0));
}
