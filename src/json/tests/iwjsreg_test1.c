#include "iowow.h"
#include "iwjsreg.h"
#include "iwlog.h"
#include <CUnit/Basic.h>
#include <unistd.h>
#include <stdlib.h>

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void _iwjsreg_basic1(void) {
  const char *path = "iwjsreg_basic1.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key1", "val1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "key2", 8217128L);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_bool(reg, "key3", true);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t val;
  rc = iwjsreg_get_i64(reg, "key2", &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(val, 8217128L);

  rc = iwjsreg_get_i64(reg, "key22", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  char *buf;
  rc = iwjsreg_get_str(reg, "key1", &buf);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(buf, "val1");
  free(buf);

  rc = iwjsreg_remove(reg, "key1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_get_i64(reg, "key1", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL(rc, 0);
}

static void _iwjsreg_basic2(void) {
  const char *path = "iwjsreg_basic2.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key1", "val1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "key2", 8217128L);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_bool(reg, "key3", true);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t val;
  rc = iwjsreg_get_i64(reg, "key2", &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(val, 8217128L);

  rc = iwjsreg_get_i64(reg, "key22", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  char *buf;
  rc = iwjsreg_get_str(reg, "key1", &buf);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(buf, "val1");
  free(buf);

  rc = iwjsreg_remove(reg, "key1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_get_i64(reg, "key1", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL(rc, 0);
}

static void _iwjsreg_merge(void) {
  const char *path = "iwjsreg_merge.dat";
  unlink(path);

  struct iwxstr *xstr = iwxstr_create_empty();
  struct iwpool *pool = iwpool_create_empty();

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);

  struct jbl_node *n, *n2;
  rc = jbn_from_json("{\"vaz\":1, \"gaz\":\"val\"}", &n, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar/zaz", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = jbn_from_json("{\"gaz\":null}", &n2, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar/zaz", n2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_copy(reg, "", pool, &n2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  fprintf(stderr, "\n");
  jbn_as_json(n2, jbl_xstr_json_printer, xstr, 0);

  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(xstr), "{\"foo\":{\"bar\":{\"vaz\":1,\"gaz\":\"val\",\"zaz\":{\"vaz\":1}}}}");

  rc = iwjsreg_sync(reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL(rc, 0);
  iwpool_destroy(pool);
  iwxstr_destroy(xstr);
}

int main(void) {
  CU_pSuite pSuite = NULL;
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }
  pSuite = CU_add_suite("iwjsreg", init_suite, clean_suite);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  int ret = 0;
  if (  NULL == CU_add_test(pSuite, "iwjsreg_basic1", _iwjsreg_basic1)
     || NULL == CU_add_test(pSuite, "iwjsreg_basic2", _iwjsreg_basic2)
     || NULL == CU_add_test(pSuite, "iwjsreg_merge", _iwjsreg_merge)) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
