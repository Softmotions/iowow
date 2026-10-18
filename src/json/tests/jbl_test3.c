// Binary (`binn` backed) JSON document API tests.
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

static void assert_as_json(struct jbl *jbl, jbl_print_flags_t pf, const char *expected) {
  char *out = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_as_json_alloc(jbl, pf, &out), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(out);
  IW_TEST_ASSERT_STR_EQUAL(out, expected);
  free(out);
}

/** Releases a stack allocated sub document returned by jbl_object_get_jbl(). */
static void destroy_sub(struct jbl *sub) {
  binn_destroy(&sub->bn);
  sub->node = 0;
}

static struct jbl* from_json(const char *json) {
  struct jbl *jbl = 0;
  iwrc rc = jbl_from_json(&jbl, json);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(jbl);
  return jbl;
}

//--- Construction and value access

static void jbl_test3_1(void) {
  struct jbl *jbl = 0;
  struct jbl *nested = 0;
  iwrc rc;

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_create_empty_object(&jbl), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(jbl), JBV_OBJECT);
  IW_TEST_ASSERT_EQUAL(jbl_count(jbl), 0);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_create_empty_object(&nested), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_int64(nested, "n", 7), 0);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_int64(jbl, "i", -5), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_f64(jbl, "f", 1.5), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_string(jbl, "s", "str"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_bool(jbl, "b", true), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_null(jbl, "nul"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_empty_array(jbl, "ea"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_empty_object(jbl, "eo"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_nested(jbl, "nested", nested), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(
    jbl_set_string_printf(jbl, "fmt", "%s-%d", "v", 3), 0);

  IW_TEST_ASSERT_EQUAL(jbl_count(jbl), 9);
  IW_TEST_ASSERT_TRUE(jbl_size(jbl) > 0);
  IW_TEST_ASSERT_EQUAL(jbl_structure_size(), sizeof(struct jbl));

  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "i"), JBV_I64);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "f"), JBV_F64);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "s"), JBV_STR);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "b"), JBV_BOOL);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "nul"), JBV_NULL);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "ea"), JBV_ARRAY);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "eo"), JBV_OBJECT);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_type(jbl, "zzz"), JBV_NONE);

  int64_t iv = 0;
  double fv = 0;
  bool bv = false;
  const char *sv = 0;

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_i64(jbl, "i", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, -5);

  // Numbers are converted between the representations
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_i64(jbl, "f", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 1);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_f64(jbl, "i", &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, -5.0, 0.0001);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_f64(jbl, "f", &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, 1.5, 0.0001);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_bool(jbl, "b", &bv), 0);
  IW_TEST_ASSERT_EQUAL(bv, true);

  size_t slen = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_str(jbl, "s", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "str");
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_str2(jbl, "s", &sv, &slen), 0);
  IW_TEST_ASSERT_EQUAL(slen, 3);
  IW_TEST_ASSERT_STR_EQUAL(sv, "str");

  // Type mismatches
  IW_TEST_ASSERT_EQUAL(jbl_object_get_i64(jbl, "s", &iv), JBL_ERROR_CREATION);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_f64(jbl, "s", &fv), JBL_ERROR_CREATION);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_bool(jbl, "i", &bv), JBL_ERROR_CREATION);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_str(jbl, "i", &sv), JBL_ERROR_CREATION);
  IW_TEST_ASSERT_PTR_NULL(sv);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_str2(jbl, "zzz", &sv, &slen), JBL_ERROR_CREATION);
  IW_TEST_ASSERT_EQUAL(slen, 0);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_i64(jbl, "zzz", &iv), JBL_ERROR_CREATION);
  IW_TEST_ASSERT_EQUAL(jbl_object_get_bool(jbl, "zzz", &bv), JBL_ERROR_CREATION);

  // Sub document access
  struct jbl sub = JBL_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_jbl(jbl, "nested", &sub), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(&sub), JBV_OBJECT);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_i64(&sub, "n", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 7);
  destroy_sub(&sub);

  IW_TEST_ASSERT_EQUAL(jbl_object_get_jbl(jbl, "zzz", &sub), JBL_ERROR_CREATION);

  // Keys are required for objects and forbidden for arrays
  IW_TEST_ASSERT_EQUAL(jbl_set_int64(jbl, 0, 1), JBL_ERROR_INVALID);

  assert_as_json(jbl, 0,
                 "{\"i\":-5,\"f\":1.5,\"s\":\"str\",\"b\":true,\"nul\":null,\"ea\":[],"
                 "\"eo\":{},\"nested\":{\"n\":7},\"fmt\":\"v-3\"}");

  jbl_destroy(&jbl);
  jbl_destroy(&nested);
  IW_TEST_ASSERT_PTR_NULL(jbl);

  // Array document
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_create_empty_array(&jbl), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(jbl), JBV_ARRAY);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_int64(jbl, 0, 1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_string(jbl, 0, "two"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_bool(jbl, 0, false), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_null(jbl, 0), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_f64(jbl, 0, 2.5), 0);
  IW_TEST_ASSERT_EQUAL(jbl_set_int64(jbl, "k", 1), JBL_ERROR_INVALID);
  IW_TEST_ASSERT_EQUAL(jbl_count(jbl), 5);
  assert_as_json(jbl, 0, "[1,\"two\",false,null,2.5]");

  assert_as_json(jbl, JBL_PRINT_PRETTY, "[\n 1,\n \"two\",\n false,\n null,\n 2.5\n]");

  jbl_destroy(&jbl);

  // Invalid JSON documents
  IW_TEST_ASSERT_EQUAL(jbl_from_json(&jbl, "{\"a\":}"), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL(jbl);
  IW_TEST_ASSERT_EQUAL(jbl_from_json(&jbl, ""), JBL_ERROR_PARSE_JSON);

  // Scalars are valid documents as well
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_json(&jbl, "12"), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(jbl), JBV_I64);
  IW_TEST_ASSERT_EQUAL(jbl_get_i64(jbl), 12);
  assert_as_json(jbl, 0, "12");
  jbl_destroy(&jbl);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_json(&jbl, "2.5"), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(jbl), JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(jbl_get_f64(jbl), 2.5, 0.0001);
  assert_as_json(jbl, 0, "2.5");
  jbl_destroy(&jbl);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_json(&jbl, "\"str\""), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(jbl), JBV_STR);
  IW_TEST_ASSERT_STR_EQUAL(jbl_get_str(jbl), "str");
  assert_as_json(jbl, 0, "\"str\"");
  jbl_destroy(&jbl);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_json(&jbl, "true"), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(jbl), JBV_BOOL);
  assert_as_json(jbl, 0, "true");
  jbl_destroy(&jbl);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_json(&jbl, "null"), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(jbl), JBV_NULL);
  assert_as_json(jbl, 0, "null");
  jbl_destroy(&jbl);
  rc = jbl_from_json_printf(&jbl, "{\"%s\":%d}", "a", 1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  assert_as_json(jbl, 0, "{\"a\":1}");
  jbl_destroy(&jbl);
}

//--- Serialization

struct serialize_ctx {
  struct iwxstr *xstr;
  int            calls;
  size_t         total;
};

static bool _serialize_consumer(const uint8_t *buf, size_t bufsz, void *op) {
  struct serialize_ctx *ctx = op;
  ++ctx->calls;
  if (!buf && !bufsz) {
    return true;
  }
  ctx->total += bufsz;
  return iwxstr_cat(ctx->xstr, buf, bufsz) == 0;
}

static bool _serialize_consumer_abort(const uint8_t *buf, size_t bufsz, void *op) {
  (void) buf;
  (void) bufsz;
  (void) op;
  return false;
}

static void jbl_test3_2(void) {
  struct jbl *jbl = from_json("{\"a\":[1,2,3],\"s\":\"str\",\"n\":{\"b\":true}}");

  size_t ssz = jbl_serialized_size(jbl);
  IW_TEST_ASSERT_TRUE(ssz > 0);

  uint8_t *buf = malloc(ssz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(buf);

  // Serialize into an insufficient buffer
  if (ssz > 1) {
    IW_TEST_ASSERT_NOT_EQUAL(jbl_serialize_into(jbl, buf, ssz - 1), 0);
  }
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_serialize_into(jbl, buf, ssz), 0);

  // Copy deserialization
  struct jbl *copy = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_create_from_buf(&copy, buf, ssz, false), 0);
  assert_as_json(copy, 0, "{\"a\":[1,2,3],\"s\":\"str\",\"n\":{\"b\":true}}");
  jbl_destroy(&copy);

  // Wrap deserialization: the buffer must outlive the document
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_create_from_buf(&copy, buf, ssz, true), 0);
  assert_as_json(copy, 0, "{\"a\":[1,2,3],\"s\":\"str\",\"n\":{\"b\":true}}");
  jbl_destroy(&copy);

  // Malformed buffer
  IW_TEST_ASSERT_EQUAL(jbl_create_from_buf(&copy, buf, 1, false), JBL_ERROR_INVALID_BUFFER);
  IW_TEST_ASSERT_PTR_NULL(copy);
  IW_TEST_ASSERT_EQUAL(jbl_create_from_buf(&copy, buf, 0, true), JBL_ERROR_INVALID_BUFFER);

  // Streaming serialization
  struct iwxstr *xstr = iwxstr_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(xstr);
  struct serialize_ctx ctx = { .xstr = xstr };
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_serialize(jbl, _serialize_consumer, &ctx), 0);
  IW_TEST_ASSERT_EQUAL(ctx.total, ssz);
  IW_TEST_ASSERT_MEM_EQUAL(iwxstr_ptr(xstr), buf, ssz);

  // Consumer abort is reported as an error
  IW_TEST_ASSERT_EQUAL(jbl_serialize(jbl, _serialize_consumer_abort, 0), IW_ERROR_FAIL);

  // init_from_buf() on an initialized document
  struct jbl doc = JBL_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_init_from_buf(&doc, buf, ssz, false), 0);
  assert_as_json(&doc, 0, "{\"a\":[1,2,3],\"s\":\"str\",\"n\":{\"b\":true}}");
  jbl_reset(&doc);
  // A reset document has a zeroed binn value, which is a NULL binn value
  IW_TEST_ASSERT_EQUAL(jbl_type(&doc), JBV_NULL);

  // Clone and reset the source
  struct jbl *clone = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_clone(jbl, &clone), 0);
  jbl_destroy(&jbl);
  assert_as_json(clone, 0, "{\"a\":[1,2,3],\"s\":\"str\",\"n\":{\"b\":true}}");
  jbl_destroy(&clone);

  free(buf);
  iwxstr_destroy(xstr);
}

//--- Value accessors

static void jbl_test3_3(void) {
  // Scalar documents are accessed as sub documents of a container
  struct jbl *root = from_json(
    "{\"i\":1234567890123,\"s\":\"hello\",\"es\":\"\",\"d\":2.25,\"b\":true}");

  struct jbl i = JBL_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_jbl(root, "i", &i), 0);
  IW_TEST_ASSERT_EQUAL(jbl_get_i64(&i), 1234567890123LL);
  IW_TEST_ASSERT_EQUAL(jbl_get_i32(&i), (int32_t) 1234567890123LL);
  IW_TEST_ASSERT_DOUBLE_EQUAL(jbl_get_f64(&i), 1234567890123.0, 0.001);
  IW_TEST_ASSERT_PTR_NULL(jbl_get_str(&i));
  destroy_sub(&i);

  struct jbl s = JBL_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_jbl(root, "s", &s), 0);
  IW_TEST_ASSERT_STR_EQUAL(jbl_get_str(&s), "hello");
  size_t len = 0;
  IW_TEST_ASSERT_STR_EQUAL(jbl_get_str2(&s, &len), "hello");
  IW_TEST_ASSERT_EQUAL(len, 5);
  IW_TEST_ASSERT_STR_EQUAL(jbl_get_str2(&s, 0), "hello");
  IW_TEST_ASSERT_EQUAL(jbl_get_i64(&s), 0);

  char buf[8];
  memset(buf, 'x', sizeof(buf));
  IW_TEST_ASSERT_EQUAL(jbl_copy_strn(&s, buf, sizeof(buf)), 5);
  IW_TEST_ASSERT_STR_EQUAL(buf, "hello");

  // An exact size buffer is not NUL terminated
  memset(buf, 'x', sizeof(buf));
  IW_TEST_ASSERT_EQUAL(jbl_copy_strn(&s, buf, 5), 5);
  IW_TEST_ASSERT_NSTR_EQUAL(buf, "hello", 5);

  // A short buffer is truncated, there is no room for the terminator
  memset(buf, 'x', sizeof(buf));
  IW_TEST_ASSERT_EQUAL(jbl_copy_strn(&s, buf, 3), 3);
  IW_TEST_ASSERT_NSTR_EQUAL(buf, "hel", 3);
  IW_TEST_ASSERT_EQUAL(buf[3], 'x');

  IW_TEST_ASSERT_EQUAL(jbl_copy_strn(&s, buf, 0), 0);
  destroy_sub(&s);

  // Empty string
  struct jbl es = JBL_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_jbl(root, "es", &es), 0);
  IW_TEST_ASSERT_STR_EQUAL(jbl_get_str(&es), "");
  IW_TEST_ASSERT_EQUAL(jbl_copy_strn(&es, buf, sizeof(buf)), 0);
  IW_TEST_ASSERT_STR_EQUAL(buf, "");
  destroy_sub(&es);

  struct jbl d = JBL_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_jbl(root, "d", &d), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(jbl_get_f64(&d), 2.25, 0.0001);
  destroy_sub(&d);

  struct jbl b = JBL_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_object_get_jbl(root, "b", &b), 0);
  IW_TEST_ASSERT_EQUAL(jbl_get_i64(&b), 0); // Booleans are not integers
  destroy_sub(&b);

  jbl_destroy(&root);
}

//--- DOM conversion

static void jbl_test3_4(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl *jbl = from_json("{\"a\":[1,2],\"s\":\"str\",\"o\":{\"b\":null}}");

  struct jbl_node *node = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_to_node(jbl, &node, true, pool), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(node);
  IW_TEST_ASSERT_EQUAL(node->type, JBV_OBJECT);

  // The cloned tree is independent of the document
  jbl_destroy(&jbl);
  char *out = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json_alloc(node, 0, &out), 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"a\":[1,2],\"s\":\"str\",\"o\":{\"b\":null}}");
  free(out);

  // Node to document
  struct jbl *back = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_node(&back, node), 0);
  assert_as_json(back, 0, "{\"a\":[1,2],\"s\":\"str\",\"o\":{\"b\":null}}");
  jbl_destroy(&back);

  // Non container nodes are rejected
  struct jbl_node *scalar;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(node, "/s", &scalar), 0);
  IW_TEST_ASSERT_EQUAL(jbl_from_node(&back, scalar), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbl_from_node(&back, 0), IW_ERROR_INVALID_ARGS);

  // Fill an existing document
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_create_empty_object(&back), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_fill_from_node(back, node), 0);
  assert_as_json(back, 0, "{\"a\":[1,2],\"s\":\"str\",\"o\":{\"b\":null}}");

  // A `JBV_NONE` node empties the document
  struct jbl_node empty_node;
  memset(&empty_node, 0, sizeof(empty_node));
  empty_node.type = JBV_NONE;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_fill_from_node(back, &empty_node), 0);
  // The document value is reset to the zero binn value (JSON null)
  IW_TEST_ASSERT_EQUAL(jbl_type(back), JBV_NULL);

  IW_TEST_ASSERT_EQUAL(jbl_fill_from_node(0, node), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbl_fill_from_node(back, 0), IW_ERROR_INVALID_ARGS);
  jbl_destroy(&back);

  // Scalar documents are converted to a single node tree
  struct jbl *scal = 0;
  struct jbl_node *snode = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_json(&scal, "42"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_to_node(scal, &snode, true, pool), 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(snode);
  IW_TEST_ASSERT_EQUAL(snode->type, JBV_I64);
  IW_TEST_ASSERT_EQUAL(snode->vi64, 42);
  jbl_destroy(&scal);
  char *sout = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json_alloc(snode, 0, &sout), 0);
  IW_TEST_ASSERT_STR_EQUAL(sout, "42");
  free(sout);

  // No string cloning: the tree references the document memory
  struct jbl *jbl2 = from_json("{\"s\":\"str\"}");
  struct jbl_node *raw = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_to_node(jbl2, &raw, false, pool), 0);
  struct jbl_node *raws;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(raw, "/s", &raws), 0);
  IW_TEST_ASSERT_STR_EQUAL(raws->vptr, "str");
  jbl_destroy(&jbl2);

  iwpool_destroy(pool);
}

//--- JSON pointer

static void jbl_test3_5(void) {
  struct jbl *jbl = from_json("{\"a\":{\"b\":[10,20,{\"c\":\"x\"}]},\"n\":null}");

  struct jbl *at = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_at(jbl, "/a/b/1", &at), 0);
  IW_TEST_ASSERT_EQUAL(jbl_get_i64(at), 20);
  jbl_destroy(&at);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_at(jbl, "/a/b/*/c", &at), 0);
  IW_TEST_ASSERT_STR_EQUAL(jbl_get_str(at), "x");
  jbl_destroy(&at);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_at(jbl, "/a/b/2", &at), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(at), JBV_OBJECT);
  jbl_destroy(&at);

  // A missing path sets the result to zero
  at = (void*) 1;
  IW_TEST_ASSERT_EQUAL(jbl_at(jbl, "/a/zzz", &at), JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_PTR_NULL(at);

  IW_TEST_ASSERT_EQUAL(jbl_at(jbl, "bad", &at), JBL_ERROR_JSON_POINTER);

  // Invalid pointer index
  IW_TEST_ASSERT_EQUAL(jbl_at(jbl, "/a/b/7", &at), JBL_ERROR_PATH_NOTFOUND);

  // Empty pointer returns the document itself
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_at(jbl, "", &at), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(at), JBV_OBJECT);
  char *out = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_as_json_alloc(at, 0, &out), 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"a\":{\"b\":[10,20,{\"c\":\"x\"}]},\"n\":null}");
  free(out);
  jbl_destroy(&at);

  // Pre-parsed pointer
  struct jbl_ptr *jp = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc("/n", &jp), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_at2(jbl, jp, &at), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(at), JBV_NULL);
  jbl_destroy(&at);
  free(jp);

  IW_TEST_ASSERT_EQUAL_FATAL(jbl_ptr_alloc("", &jp), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_at2(jbl, jp, &at), 0);
  IW_TEST_ASSERT_EQUAL(jbl_type(at), JBV_OBJECT);
  jbl_destroy(&at);
  free(jp);

  jbl_destroy(&jbl);

  // A null document is rejected by the printer
  IW_TEST_ASSERT_EQUAL(jbl_as_json(0, jbl_count_json_printer, &(int){0}, 0), IW_ERROR_INVALID_ARGS);
}

//--- Patching

static void jbl_test3_6(void) {
  struct jbl *jbl = from_json("{\"a\":1,\"b\":{\"c\":2},\"arr\":[1,2,3]}");
  iwrc rc;

  struct jbl_node *v1 = 0, *v2 = 0;
  struct jbl *vjbl = from_json("{\"x\":true}");
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_to_node(vjbl, &v1, true, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_clone(v1, &v2, pool), 0);
  jbl_destroy(&vjbl);

  struct jbl_patch p[] = {
    { .op = JBP_REPLACE, .path = "/a", .vnode = v1 },
    { .op = JBP_REMOVE, .path = "/b" },
    { .op = JBP_ADD, .path = "/arr/-", .vnode = v2 },
  };
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_patch(jbl, p, 3), 0);
  assert_as_json(jbl, 0, "{\"arr\":[1,2,3,{\"x\":true}],\"a\":{\"x\":true}}");

  // No operations is a no-op
  IW_TEST_ASSERT_EQUAL(jbl_patch(jbl, p, 0), 0);
  IW_TEST_ASSERT_EQUAL(jbl_patch(0, p, 1), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbl_patch(jbl, 0, 1), IW_ERROR_INVALID_ARGS);

  // Patch document
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_patch_from_json(jbl, "[{\"op\":\"add\",\"path\":\"/n\",\"value\":7}]"), 0);
  assert_as_json(jbl, 0, "{\"arr\":[1,2,3,{\"x\":true}],\"a\":{\"x\":true},\"n\":7}");

  // An object document is applied as a JSON Merge Patch
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_patch_from_json(jbl, "{\"m\":{\"k\":\"v\"}}"), 0);
  assert_as_json(jbl, 0,
                 "{\"arr\":[1,2,3,{\"x\":true}],\"a\":{\"x\":true},\"n\":7,\"m\":{\"k\":\"v\"}}");

  // A null merge patch value removes the member
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_patch_from_json(jbl, "{\"n\":null,\"m\":null}"), 0);
  assert_as_json(jbl, 0, "{\"arr\":[1,2,3,{\"x\":true}],\"a\":{\"x\":true}}");

  // An empty merge patch document is a no-op
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_patch_from_json(jbl, "{}"), 0);
  assert_as_json(jbl, 0, "{\"arr\":[1,2,3,{\"x\":true}],\"a\":{\"x\":true}}");

  // A merge patch of a scalar document replaces its value with an object
  struct jbl *scal = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_from_json(&scal, "1"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_patch_from_json(scal, "{\"a\":2}"), 0);
  assert_as_json(scal, 0, "{\"a\":2}");
  jbl_destroy(&scal);

  // Scalar patch documents are invalid
  IW_TEST_ASSERT_EQUAL(jbl_patch_from_json(jbl, "1"), JBL_ERROR_PATCH_INVALID);
  IW_TEST_ASSERT_EQUAL(jbl_patch_from_json(jbl, "\"str\""), JBL_ERROR_PATCH_INVALID);
  IW_TEST_ASSERT_EQUAL(jbl_patch_from_json(jbl, "[1]"), JBL_ERROR_PATCH_INVALID);
  IW_TEST_ASSERT_EQUAL(jbl_patch_from_json(jbl, "[{\"op\":\"zzz\",\"path\":\"/n\",\"value\":1}]"),
                       JBL_ERROR_PATCH_INVALID_OP);
  IW_TEST_ASSERT_EQUAL(jbl_patch_from_json(jbl, "{"), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbl_patch_from_json(0, "[]"), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbl_patch_from_json(jbl, 0), IW_ERROR_INVALID_ARGS);

  // Merge patch
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_merge_patch(jbl, "{\"a\":{\"y\":1},\"n\":null}"), 0);
  assert_as_json(jbl, 0, "{\"arr\":[1,2,3,{\"x\":true}],\"a\":{\"x\":true,\"y\":1}}");

  // A malformed merge patch document must be reported
  rc = jbl_merge_patch(jbl, "{\"a\":");
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  rc = jbl_merge_patch(jbl, "12");
  IW_TEST_ASSERT_EQUAL(rc, 0);
  assert_as_json(jbl, 0, "12");
  jbl_destroy(&jbl);

  // Merge patch of a document by another document
  jbl = from_json("{\"a\":1}");
  struct jbl *patch = from_json("{\"b\":2}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_merge_patch_jbl(jbl, patch), 0);
  assert_as_json(jbl, 0, "{\"a\":1,\"b\":2}");
  jbl_destroy(&patch);
  jbl_destroy(&jbl);

  IW_TEST_ASSERT_EQUAL(jbl_merge_patch(0, "{}"), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(jbl_merge_patch_jbl(0, 0), IW_ERROR_INVALID_ARGS);

  iwpool_destroy(pool);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(jbl_test3_1),
  IW_TEST_CASE(jbl_test3_2),
  IW_TEST_CASE(jbl_test3_3),
  IW_TEST_CASE(jbl_test3_4),
  IW_TEST_CASE(jbl_test3_5),
  IW_TEST_CASE(jbl_test3_6),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("jbl_test3", cases, init_suite, 0));
}
