#include "iwjson.h"
#include "iwjson_internal.h"
#include "iwutils.h"

#include <stdlib.h>
#include <CUnit/Basic.h>

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void test_jbn_xml(void) {
  IWXSTR *xstr = iwxstr_create();
  struct iwpool *pool = iwpool_create_empty();
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);

  JBL_NODE n;
  const char *val = "{"
                    "\">attr\":\"attrvalue\""
                    "\">attr2\":\"ss < ' xx\""
                    ",\"foo\":\"bar\""
                    ",\"\":\"bo\\ndy 1 < 2 \""
                    ",\"arr\":[1,2,3,{\"obj\":\"k&k\"}]"
                    ",\"nested\":{\"baz\":{\"zaz\":true,\"arr\":[1,3.36,true,\"a\"]}}"
                    "}";
  iwrc rc = jbn_from_json(val, &n, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = jbn_as_xml(n, &(struct jbn_as_xml_spec) {
    .flags = JBL_PRINT_PRETTY,
    .print_xml_header = true,
    .printer_fn = jbl_xstr_json_printer,
    .printer_fn_data = xstr,
  });
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  char *buf = iwu_file_read_as_buf("data/jbl_test2.001.expected.xml");
  CU_ASSERT_PTR_NOT_NULL_FATAL(buf);
  CU_ASSERT_EQUAL(strcmp(buf, iwxstr_ptr(xstr)), 0);

  iwpool_destroy(pool);
  iwxstr_destroy(xstr);
  free(buf);
}

int main(void) {
  CU_pSuite pSuite = NULL;
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }
  pSuite = CU_add_suite("jbl_test1", init_suite, clean_suite);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (NULL == CU_add_test(pSuite, "test_jbn_xml", test_jbn_xml)) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
