#include "iwlog.h"
#include "iwjson.h"
#include "iwutils.h"

#include <stdlib.h>
#include "tests.h"

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

static void test_jbn_xml(void) {
  struct iwxstr *xstr = iwxstr_create_empty();
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *n;
  const char *val = "{"
                    "\">attr\":\"attrvalue\""
                    "\">attr2\":\"ss < ' xx\""
                    ",\"foo\":\"bar\""
                    ",\"\":\"bo\\ndy 1 < 2 \""
                    ",\"arr\":[1,2,3,{\"obj\":\"k&k\"}]"
                    ",\"nested\":{\"baz\":{\"zaz\":true,\"arr\":[1,3.36,true,\"a\"]}}"
                    "}";
  iwrc rc = jbn_from_json(val, &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = jbn_as_xml(n, &(struct jbn_as_xml_spec) {
    .flags = JBL_PRINT_PRETTY,
    .print_xml_header = true,
    .printer_fn = jbl_xstr_json_printer,
    .printer_fn_data = xstr,
  });
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  char *buf = iwu_file_read_as_buf("data/jbl_test2.001.expected.xml");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(buf);
  IW_TEST_ASSERT_EQUAL(strcmp(buf, iwxstr_ptr(xstr)), 0);

  iwpool_destroy(pool);
  iwxstr_destroy(xstr);
  free(buf);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(test_jbn_xml),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("jbl_test1", cases, init_suite, 0));
}

