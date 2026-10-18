// DOM tree (`struct jbl_node`) core API tests.
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

/** Asserts that the `node` tree prints as the `expected` JSON text. */
static void assert_as_json(struct jbl_node *node, jbl_print_flags_t pf, const char *expected) {
  char *out = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json_alloc(node, pf, &out), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(out);
  IW_TEST_ASSERT_STR_EQUAL(out, expected);
  free(out);
}

/** Creates a new tree from `json` text, aborts the case on failure. */
static struct jbl_node* from_json(struct iwpool *pool, const char *json) {
  struct jbl_node *n = 0;
  iwrc rc = jbn_from_json(json, &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(n);
  return n;
}

//--- Values

static void jbn_test1_values(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *n = from_json(pool, "{\"i\":12,\"f\":2.5,\"s\":\"bar\",\"b\":true,\"nul\":null}");

  int64_t iv = 0;
  double fv = 0;
  struct jbl_node *v;

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/i", &v), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_int_value(v, &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 12);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_double_value(v, &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, 12.0, 0.0001);

  // Float to int conversion is a truncation
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/f", &v), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_int_value(v, &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 2);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_double_value(v, &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, 2.5, 0.0001);

  // Non numeric values are rejected
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/s", &v), 0);
  IW_TEST_ASSERT_EQUAL(jbn_int_value(v, &iv), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_double_value(v, &fv), IW_ERROR_INVALID_ARGS);

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/b", &v), 0);
  IW_TEST_ASSERT_EQUAL(jbn_int_value(v, &iv), IW_ERROR_INVALID_ARGS);

  // Plain value copy: only the value part is transferred
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/f", &v), 0);
  struct jbl_plain_value pv;
  jbl_node_as_plain_value(v, &pv);
  IW_TEST_ASSERT_EQUAL(pv.type, JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(pv.vf64, 2.5, 0.0001);

  struct jbl_node *target;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/i", &target), 0);
  jbl_plain_value_set_node(&pv, target);
  IW_TEST_ASSERT_EQUAL(target->type, JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(target->vf64, 2.5, 0.0001);
  IW_TEST_ASSERT_STR_EQUAL(target->key, "i");
  assert_as_json(n, 0, "{\"i\":2.5,\"f\":2.5,\"s\":\"bar\",\"b\":true,\"nul\":null}");

  // jbn_data() resets the value part keeping the node identity
  jbn_data(v);
  IW_TEST_ASSERT_EQUAL(v->type, JBV_NONE);
  IW_TEST_ASSERT_PTR_NULL(v->child);
  IW_TEST_ASSERT_STR_EQUAL(v->key, "f");

  // jbn_apply_from() copies the value part and the children
  struct jbl_node *src;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/nul", &src), 0);
  jbn_apply_from(target, src);
  IW_TEST_ASSERT_EQUAL(target->type, JBV_NULL);
  IW_TEST_ASSERT_STR_EQUAL(target->key, "i");

  iwpool_destroy(pool);
}

//--- Item creation

static void jbn_test1_add_items(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{}");

  struct jbl_node *arr, *obj, *str;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(root, "str", "value", -1, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(root, "empty", 0, -1, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(root, "part", "abcdef", 3, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_null(root, "null", pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_i64(root, "i64", -777, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_f64(root, "f64", 1.25, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_bool(root, "bool", true, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_obj(root, "obj", &obj, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_arr(root, "arr", &arr, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(obj, "nested", "n", -1, &str, pool), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(str);

  // Array elements are indexed automatically, the key is not allowed
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_i64(arr, 0, 1, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_i64(arr, "ignored", 2, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(arr, 0, "three", -1, 0, pool), 0);

  IW_TEST_ASSERT_EQUAL(jbn_length(root), 9);
  IW_TEST_ASSERT_EQUAL(jbn_length(arr), 3);
  IW_TEST_ASSERT_EQUAL(arr->child->klidx, 0);
  IW_TEST_ASSERT_EQUAL(arr->child->next->klidx, 1);
  IW_TEST_ASSERT_EQUAL(arr->child->next->next->klidx, 2);
  IW_TEST_ASSERT_PTR_NULL(arr->child->key);

  assert_as_json(root, 0,
                 "{\"str\":\"value\",\"empty\":\"\",\"part\":\"abc\",\"null\":null,\"i64\":-777,"
                 "\"f64\":1.25,\"bool\":true,\"obj\":{\"nested\":\"n\"},\"arr\":[1,2,\"three\"]}");

  // Object nodes require a key
  IW_TEST_ASSERT_EQUAL(jbn_add_item_str(root, 0, "v", -1, 0, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_add_item_i64(root, 0, 1, 0, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_add_item_obj(root, 0, 0, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_add_item_arr(root, 0, 0, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_add_item_null(root, 0, pool), IW_ERROR_INVALID_ARGS);

  // Scalar parents are rejected
  struct jbl_node *scalar;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/i64", &scalar), 0);
  IW_TEST_ASSERT_EQUAL(jbn_add_item_str(scalar, "k", "v", -1, 0, pool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_add_item_str(0, "k", "v", -1, 0, pool), IW_ERROR_INVALID_ARGS);

  // Removal from the middle/beginning/end of the sibling list
  struct jbl_node *i64node;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/i64", &i64node), 0);
  jbn_remove_item(root, i64node);
  IW_TEST_ASSERT_PTR_NULL(i64node->parent);
  IW_TEST_ASSERT_EQUAL(jbn_length(root), 8);

  struct jbl_node *first = root->child;
  jbn_remove_item(root, first);
  IW_TEST_ASSERT_EQUAL(jbn_length(root), 7);
  assert_as_json(root, 0,
                 "{\"empty\":\"\",\"part\":\"abc\",\"null\":null,\"f64\":1.25,"
                 "\"bool\":true,\"obj\":{\"nested\":\"n\"},\"arr\":[1,2,\"three\"]}");

  struct jbl_node *last = root->child->prev;
  jbn_remove_item(root, last);
  IW_TEST_ASSERT_EQUAL(jbn_length(root), 6);
  IW_TEST_ASSERT_EQUAL(last->type, JBV_ARRAY);

  // Removing the only child
  struct jbl_node *arr2;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_arr(root, "arr2", &arr2, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_i64(arr2, 0, 1, 0, pool), 0);
  jbn_remove_item(arr2, arr2->child);
  IW_TEST_ASSERT_PTR_NULL(arr2->child);
  assert_as_json(arr2, 0, "[]");

  iwpool_destroy(pool);
}

//--- Lookup

static void jbn_test1_get(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"a\":{\"b\":[10,20,30]},\"c\":\"x\"}");
  struct jbl_node *n = 0;
  iwrc rc;

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_get(root, "a", 0, &n), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(n);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_OBJECT);

  rc = jbn_get(root, "zzz", 0, &n);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_PTR_NULL(n);

  struct jbl_node *arr;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_get(root, "a", 0, &arr), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_get(arr, "b", 0, &arr), 0);
  IW_TEST_ASSERT_EQUAL(arr->type, JBV_ARRAY);
  IW_TEST_ASSERT_EQUAL(jbn_length(arr), 3);

  // The `key` argument is ignored for arrays and may be zero
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_get(arr, 0, 1, &n), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(n);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_I64);
  IW_TEST_ASSERT_EQUAL(n->vi64, 20);

  rc = jbn_get(arr, 0, 3, &n);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_PTR_NULL(n);

  rc = jbn_get(arr, 0, -1, &n);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);

  // Scalar node has no children
  struct jbl_node *scalar;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_get(root, "c", 0, &scalar), 0);
  IW_TEST_ASSERT_EQUAL(jbn_get(scalar, "c", 0, &n), JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_EQUAL(jbn_length(scalar), 0);

  // Invalid arguments
  IW_TEST_ASSERT_EQUAL(jbn_get(0, "a", 0, &n), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_get(root, "a", 0, 0), IW_ERROR_INVALID_ARGS);

  // Empty pointer points to the root
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "", &n), 0);
  IW_TEST_ASSERT_EQUAL(n, root);

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/a/b/2", &n), 0);
  IW_TEST_ASSERT_EQUAL(n->vi64, 30);

  rc = jbn_at(root, "/a/b/5", &n);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_PTR_NULL(n);

  rc = jbn_at(root, "a", &n);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_JSON_POINTER);

  struct jbl_ptr *jp;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("/a/b/1", &jp, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at2(root, jp, &n), 0);
  IW_TEST_ASSERT_EQUAL(n->vi64, 20);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("", &jp, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at2(root, jp, &n), 0);
  IW_TEST_ASSERT_EQUAL(n, root);

  iwpool_destroy(pool);
}

//--- Comparison

static void jbn_test1_compare(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *n1 = from_json(pool, "{\"a\":1,\"b\":[1,2,{\"x\":true}],\"c\":\"s\",\"d\":1.5,\"e\":null}");
  struct jbl_node *n2 = from_json(pool, "{\"b\":[1,2,{\"x\":true}],\"c\":\"s\",\"a\":1,\"d\":1.5,\"e\":null}");
  struct jbl_node *n3 = from_json(pool, "{\"a\":1,\"b\":[1,2,{\"x\":false}],\"c\":\"s\",\"d\":1.5,\"e\":null}");
  struct jbl_node *n4 = from_json(pool, "{\"a\":1,\"b\":[1,2],\"c\":\"s\",\"d\":1.5,\"e\":null}");

  iwrc rc = 0;

  // Object key order does not matter
  IW_TEST_ASSERT_EQUAL(jbn_compare_nodes(n1, n2, &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);

  // A different nested value is reported as a difference
  IW_TEST_ASSERT_NOT_EQUAL(jbn_compare_nodes(n1, n3, &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);

  // Shorter arrays are lesser
  IW_TEST_ASSERT_TRUE(jbn_compare_nodes(n4, n1, &rc) < 0);
  IW_TEST_ASSERT_TRUE(jbn_compare_nodes(n1, n4, &rc) > 0);

  // Type mismatch is reported by the positive/negative distance of the types
  struct jbl_node *s, *i, *f, *b, *nul, *obj, *arr;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n1, "/c", &s), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n1, "/a", &i), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n1, "/d", &f), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n1, "/b/2/x", &b), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n1, "/e", &nul), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n1, "/b/2", &obj), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n1, "/b", &arr), 0);

  IW_TEST_ASSERT_TRUE(jbn_compare_nodes(i, s, &rc) != 0);
  IW_TEST_ASSERT_TRUE(jbn_compare_nodes(i, f, &rc) != 0);
  IW_TEST_ASSERT_TRUE(jbn_compare_nodes(obj, arr, &rc) != 0);
  IW_TEST_ASSERT_EQUAL(jbn_compare_nodes(s, s, &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_compare_nodes(nul, nul, &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_compare_nodes(b, b, &rc), 0);

  // Zero nodes: NULL is lesser than any node
  IW_TEST_ASSERT_EQUAL(jbn_compare_nodes(0, 0, &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_compare_nodes(0, i, &rc), -1);
  IW_TEST_ASSERT_EQUAL(jbn_compare_nodes(i, 0, &rc), 1);

  // Different string of the same length
  struct jbl_node *s2 = from_json(pool, "\"q\"");
  IW_TEST_ASSERT_NOT_EQUAL(jbn_compare_nodes(s, s2, &rc), 0);
  IW_TEST_ASSERT_NOT_EQUAL(jbn_compare_nodes(s2, s, &rc), 0);

  // Path based comparison
  IW_TEST_ASSERT_EQUAL(jbn_path_compare(n1, n2, "/a", 0, &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(jbn_path_compare(n1, n2, "/a", JBV_I64, &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(jbn_path_compare(n1, n2, "/a", JBV_STR, &rc), -2);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_TYPE_MISMATCHED);

  IW_TEST_ASSERT_EQUAL(jbn_paths_compare(n1, "/c", n2, "/c", JBV_STR, &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_paths_compare(n1, "/c", n2, "/a", 0, &rc) != 0, true);

  // Missing paths are treated as an empty value
  IW_TEST_ASSERT_EQUAL(jbn_paths_compare(n1, "/zzz", n2, "/zzz", 0, &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(jbn_paths_compare(n1, "/zzz", n2, "/a", 0, &rc), -1);
  IW_TEST_ASSERT_EQUAL(jbn_paths_compare(n1, "/zzz", n2, "/a", JBV_I64, &rc), -2);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_TYPE_MISMATCHED);

  IW_TEST_ASSERT_EQUAL(jbn_paths_compare(n1, "bad", n2, "/a", 0, &rc), -2);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_JSON_POINTER);

  // Scalar comparators
  IW_TEST_ASSERT_EQUAL(jbn_path_compare_str(n1, "/c", "s", &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  IW_TEST_ASSERT_NOT_EQUAL(jbn_path_compare_str(n1, "/c", "q", &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_path_compare_str(n1, "/zzz", "s", &rc), -2);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);

  IW_TEST_ASSERT_EQUAL(jbn_path_compare_i64(n1, "/a", 1, &rc), 0);
  IW_TEST_ASSERT_NOT_EQUAL(jbn_path_compare_i64(n1, "/a", 2, &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_path_compare_i64(n1, "/zzz", 1, &rc), -2);

  IW_TEST_ASSERT_EQUAL(jbn_path_compare_f64(n1, "/d", 1.5, &rc), 0);
  IW_TEST_ASSERT_NOT_EQUAL(jbn_path_compare_f64(n1, "/d", 1.25, &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_path_compare_f64(n1, "/zzz", 1.5, &rc), -2);

  IW_TEST_ASSERT_EQUAL(jbn_path_compare_bool(n1, "/b/2/x", true, &rc), 0);
  IW_TEST_ASSERT_NOT_EQUAL(jbn_path_compare_bool(n1, "/b/2/x", false, &rc), 0);
  IW_TEST_ASSERT_EQUAL(jbn_path_compare_bool(n1, "/zzz", true, &rc), -2);

  iwpool_destroy(pool);
}

//--- Traversal

struct visit_log {
  struct iwxstr *xstr;
  char          *skip_key;
};

static jbn_visitor_cmd_t _visit_logger(
  int              lvl,
  struct jbl_node *n,
  const char      *key,
  int              klidx,
  struct jbn_vctx *vctx,
  iwrc            *rc) {
  struct visit_log *log = vctx->op;
  if (lvl < 0) {
    iwxstr_cat(log->xstr, "|EOF", 4);
    return JBL_VCMD_OK;
  }
  char buf[128];
  if (key) {
    snprintf(buf, sizeof(buf), "|%d:%s=%d", lvl, key, (int) n->type);
  } else {
    snprintf(buf, sizeof(buf), "|%d:#%d=%d", lvl, klidx, (int) n->type);
  }
  iwxstr_cat(log->xstr, buf, strlen(buf));
  if (log->skip_key && key && !strcmp(key, log->skip_key)) {
    return JBL_VCMD_SKIP_NESTED;
  }
  if (key && !strcmp(key, "stop")) {
    return JBL_VCMD_TERMINATE;
  }
  return JBL_VCMD_OK;
}

static jbn_visitor_cmd_t _visit_delete(
  int              lvl,
  struct jbl_node *n,
  const char      *key,
  int              klidx,
  struct jbn_vctx *vctx,
  iwrc            *rc) {
  if (lvl < 0) {
    return JBL_VCMD_OK;
  }
  if (key && !strcmp(key, "delete_me")) {
    return JBN_VCMD_DELETE;
  }
  return JBL_VCMD_OK;
}

static void jbn_test1_visit(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(
    pool, "{\"a\":1,\"c\":2,\"b\":{\"c\":3,\"d\":[4,5]}}");

  struct iwxstr *xstr = iwxstr_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(xstr);

  struct visit_log log = { .xstr = xstr };
  struct jbn_vctx vctx = { .root = root, .op = &log };
  iwrc rc = jbn_visit(root, 0, &vctx, _visit_logger);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(
    iwxstr_ptr(xstr),
    "|0:a=3|0:c=3|0:b=6|1:c=3|1:d=7|2:#0=3|2:#1=3|EOF");

  // Skip nested
  iwxstr_clear(xstr);
  log.skip_key = "b";
  memset(&vctx, 0, sizeof(vctx));
  vctx.root = root;
  vctx.op = &log;
  rc = jbn_visit(root, 0, &vctx, _visit_logger);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "|0:a=3|0:c=3|0:b=6|EOF");

  // Terminate
  iwxstr_clear(xstr);
  log.skip_key = 0;
  memset(&vctx, 0, sizeof(vctx));
  vctx.root = root;
  vctx.op = &log;
  struct jbl_node *root2 = from_json(pool, "{\"a\":1,\"stop\":2,\"z\":3}");
  rc = jbn_visit(root2, 0, &vctx, _visit_logger);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "|0:a=3|0:stop=3|EOF");

  // Start from a zero node: the vctx root is used
  iwxstr_clear(xstr);
  memset(&vctx, 0, sizeof(vctx));
  vctx.root = root2;
  vctx.op = &log;
  rc = jbn_visit(0, 0, &vctx, _visit_logger);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "|0:a=3|0:stop=3|EOF");

  // Invalid arguments
  struct jbn_vctx vctx_bad = { .root = root, .op = &log };
  IW_TEST_ASSERT_EQUAL(jbn_visit(root, 0, &vctx_bad, 0), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_visit(root, 0, 0, _visit_logger), IW_ERROR_INVALID_ARGS);

  // Delete nodes by visitor command
  struct jbl_node *del = from_json(
    pool, "{\"keep\":1,\"delete_me\":{\"x\":2},\"arr\":[3,4]}");
  struct jbn_vctx dctx = { .root = del };
  rc = jbn_visit(del, 0, &dctx, _visit_delete);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  assert_as_json(del, 0, "{\"keep\":1,\"arr\":[3,4]}");

  iwxstr_destroy(xstr);
  iwpool_destroy(pool);
}

static iwrc _visit2_counter(int lvl, struct jbl_node *n) {
  (void) lvl;
  (void) n;
  return 0;
}

static void jbn_test1_visit2(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"a\":{\"b\":1},\"c\":2}");
  IW_TEST_ASSERT_EQUAL(jbn_visit2(root, 0, _visit2_counter), 0);

  struct jbl_node *scalar;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/a/b", &scalar), 0);
  IW_TEST_ASSERT_EQUAL(jbn_visit2(scalar, 0, _visit2_counter), 0);
  IW_TEST_ASSERT_EQUAL(jbn_visit2(0, 0, _visit2_counter), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_visit2(root, BINN_MAX_NESTING_LEVELS + 1, _visit2_counter),
                       JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED);

  iwpool_destroy(pool);
}

//--- Detach

static void jbn_test1_detach(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"a\":{\"b\":1},\"c\":[1,2,3]}");

  struct jbl_node *d = jbn_detach(root, "/a/b");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(d);
  IW_TEST_ASSERT_PTR_NULL(d->parent);
  IW_TEST_ASSERT_EQUAL(d->vi64, 1);
  assert_as_json(root, 0, "{\"a\":{},\"c\":[1,2,3]}");

  // Missing path
  IW_TEST_ASSERT_PTR_NULL(jbn_detach(root, "/a/zzz"));

  // An invalid pointer is reported as a missing node
  IW_TEST_ASSERT_PTR_NULL(jbn_detach(root, "bad"));

  // The root itself cannot be detached: the empty pointer and `/` are not children
  IW_TEST_ASSERT_PTR_NULL(jbn_detach(root, ""));
  IW_TEST_ASSERT_PTR_NULL(jbn_detach(root, "/"));
  assert_as_json(root, 0, "{\"a\":{},\"c\":[1,2,3]}");

  // Detach an array element
  d = jbn_detach(root, "/c/1");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(d);
  IW_TEST_ASSERT_EQUAL(d->vi64, 2);
  assert_as_json(root, 0, "{\"a\":{},\"c\":[1,3]}");

  // The last array element can be detached using the `-` index
  d = jbn_detach(root, "/c/-");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(d);
  IW_TEST_ASSERT_EQUAL(d->vi64, 3);

  struct jbl_ptr *jp;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc_pool("/c/0", &jp, pool), 0);
  d = jbn_detach2(root, jp);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(d);
  IW_TEST_ASSERT_EQUAL(d->vi64, 1);
  IW_TEST_ASSERT_PTR_NULL(jbn_detach2(root, 0));

  iwpool_destroy(pool);
}

//--- Serialization

static void jbn_test1_as_json(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = from_json(pool, "{\"a\":[1,{\"b\":null}],\"c\":\"s\"}");

  assert_as_json(root, 0, "{\"a\":[1,{\"b\":null}],\"c\":\"s\"}");
  assert_as_json(root, JBL_PRINT_PRETTY,
                 "{\n \"a\": [\n  1,\n  {\n   \"b\": null\n  }\n ],\n \"c\": \"s\"\n}");
  assert_as_json(root, JBL_PRINT_PRETTY_INDENT2,
                 "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": \"s\"\n}");
  assert_as_json(root, JBL_PRINT_PRETTY_INDENT4,
                 "{\n    \"a\": [\n        1,\n        {\n            \"b\": null\n        }\n    ],\n"
                 "    \"c\": \"s\"\n}");

  // `JBV_NONE` nodes print nothing and do not produce dangling separators
  struct jbl_node *n;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/c", &n), 0);
  jbn_data(n);
  assert_as_json(root, 0, "{\"a\":[1,{\"b\":null}]}");
  assert_as_json(root, JBL_PRINT_PRETTY,
                 "{\n \"a\": [\n  1,\n  {\n   \"b\": null\n  }\n ]\n}");
  struct jbl_node *i1;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/a", &n), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(root, "/a/0", &i1), 0);
  jbn_data(i1);
  assert_as_json(n, 0, "[{\"b\":null}]");
  struct jbl_node *last = n->child->prev;
  jbn_data(last);
  assert_as_json(n, 0, "[]");
  assert_as_json(n, JBL_PRINT_PRETTY, "[]");

  // Empty containers
  struct jbl_node *empty = from_json(pool, "{}");
  assert_as_json(empty, JBL_PRINT_PRETTY, "{}");
  struct jbl_node *empty_arr = from_json(pool, "[]");
  assert_as_json(empty_arr, JBL_PRINT_PRETTY, "[]");

  // Invalid arguments
  IW_TEST_ASSERT_EQUAL(jbn_as_json(root, 0, 0, 0), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_as_json(0, jbl_xstr_json_printer, 0, 0), IW_ERROR_INVALID_ARGS);

  iwpool_destroy(pool);
}

static void jbn_test1_clone(void) {
  struct iwpool *pool = iwpool_create(512);
  struct iwpool *cpool = iwpool_create(512);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(cpool);

  struct jbl_node *root = from_json(pool, "{\"a\":[1,\"two\",{\"b\":true}],\"c\":null}");
  struct jbl_node *clone = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_clone(root, &clone, cpool), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(clone);
  IW_TEST_ASSERT_PTR_NULL(clone->parent);

  // The clone is independent of the source
  iwpool_destroy(pool);
  assert_as_json(clone, 0, "{\"a\":[1,\"two\",{\"b\":true}],\"c\":null}");

  // Clone a scalar
  struct jbl_node *scalar = clone->child->child;
  struct jbl_node *sclone = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_clone(scalar, &sclone, cpool), 0);
  IW_TEST_ASSERT_EQUAL(sclone->type, JBV_I64);
  IW_TEST_ASSERT_EQUAL(sclone->vi64, 1);
  IW_TEST_ASSERT_PTR_NULL(sclone->parent);
  IW_TEST_ASSERT_EQUAL(sclone->klidx, 0);

  struct jbl_node *invalid = 0;
  IW_TEST_ASSERT_EQUAL(jbn_clone(0, &invalid, cpool), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_PTR_NULL(invalid);

  iwpool_destroy(cpool);
}

//--- Parsing

static iwrc _free_node(int lvl, struct jbl_node *n) {
  free((void*) n->key);
  if (n->type == JBV_STR) {
    free((void*) n->vptr);
  }
  free(n);
  return 0;
}

static void jbn_test1_from_json(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *n = 0;

  // Scalar roots are supported by the DOM parser
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json(" 12 ", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_I64);
  IW_TEST_ASSERT_EQUAL(n->vi64, 12);

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("\"str\"", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_STR);
  IW_TEST_ASSERT_STR_EQUAL(n->vptr, "str");

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("null", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_NULL);

  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json_printf(&n, pool, "{\"%s\":%d}", "k", 42), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/k", &n), 0);
  IW_TEST_ASSERT_EQUAL(n->vi64, 42);

  // No pool: the tree is allocated with malloc() and must be released manually
  struct jbl_node *malloced = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("{\"a\":[1,2]}", &malloced, 0), 0);
  IW_TEST_ASSERT_PTR_NULL(malloced->parent);
  IW_TEST_ASSERT_EQUAL(jbn_visit2(malloced, 0, 0), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_visit2(malloced, 0, _free_node), 0);

  iwpool_destroy(pool);
}

//--- XML

static void jbn_test1_xml(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct iwxstr *xstr = iwxstr_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(xstr);

  struct jbl_node *root = from_json(
    pool, "{\">id\":10,\"name\":\"Jo & <hn>\",\"\":\"body\",\"arr\":[1,2]}");

  // The XML header is optional
  iwrc rc = jbn_as_xml(root, &(struct jbn_as_xml_spec) {
    .flags = JBL_PRINT_PRETTY,
    .print_xml_header = false,
    .printer_fn = jbl_xstr_json_printer,
    .printer_fn_data = xstr,
  });
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr),
                           "\n<root id=\"10\">"
                           "\n <name>Jo &#38; &#60;hn&#62;</name>"
                           "\n body"
                           "\n <arr>"
                           "\n  <item>1</item>"
                           "\n  <item>2</item>"
                           "\n </arr>"
                           "\n</root>");

  // Custom tags and header
  iwxstr_clear(xstr);
  rc = jbn_as_xml(root, &(struct jbn_as_xml_spec) {
    .print_xml_header = true,
    .root_tag = "doc",
    .array_tag = "el",
    .printer_fn = jbl_xstr_json_printer,
    .printer_fn_data = xstr,
  });
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr),
                           "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                           "<doc id=\"10\"><name>Jo &#38; &#60;hn&#62;</name>body"
                           "<arr><el>1</el><el>2</el></arr></doc>");

  // Invalid arguments
  IW_TEST_ASSERT_EQUAL(jbn_as_xml(0, &(struct jbn_as_xml_spec) {
    .print_xml_header = true,
    .printer_fn = jbl_xstr_json_printer,
    .printer_fn_data = xstr,
  }), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbn_as_xml(root, 0), IW_ERROR_INVALID_ARGS);

  iwxstr_destroy(xstr);
  iwpool_destroy(pool);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(jbn_test1_values),
  IW_TEST_CASE(jbn_test1_add_items),
  IW_TEST_CASE(jbn_test1_get),
  IW_TEST_CASE(jbn_test1_compare),
  IW_TEST_CASE(jbn_test1_visit),
  IW_TEST_CASE(jbn_test1_visit2),
  IW_TEST_CASE(jbn_test1_detach),
  IW_TEST_CASE(jbn_test1_as_json),
  IW_TEST_CASE(jbn_test1_clone),
  IW_TEST_CASE(jbn_test1_from_json),
  IW_TEST_CASE(jbn_test1_xml),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("jbn_test1", cases, init_suite, 0));
}
