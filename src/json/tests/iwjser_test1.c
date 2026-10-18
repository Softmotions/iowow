// JSON text parser and serializer primitives tests.
#include "iwlog.h"
#include "iwxstr.h"
#include "iwutils.h"
#include "iwpool.h"

#include "iwjson.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tests.h"

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

static struct jbl_node* parse(struct iwpool *pool, const char *json) {
  struct jbl_node *n = 0;
  iwrc rc = jbn_from_json(json, &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(n);
  return n;
}

static char* print(struct jbl_node *node, jbl_print_flags_t pf) {
  char *out = 0;
  iwrc rc = jbn_as_json_alloc(node, pf, &out);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(out);
  return out;
}

//--- Parsing: string escapes

static void iwjser_test1_escapes(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *n = parse(pool, "{\"s\":\"a\\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti\"}");
  struct jbl_node *s;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/s", &s), 0);
  IW_TEST_ASSERT_EQUAL(s->type, JBV_STR);
  const char *expected = "a\"b\\c/d\be\ff\ng\rh\ti";
  IW_TEST_ASSERT_EQUAL(s->vsize, (int) strlen(expected));
  IW_TEST_ASSERT_NSTR_EQUAL(s->vptr, expected, strlen(expected));

  // Unicode escape
  n = parse(pool, "{\"s\":\"\\u0041\\u00e9\\u04AF\"}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/s", &s), 0);
  IW_TEST_ASSERT_EQUAL(s->vsize, 5);
  IW_TEST_ASSERT_NSTR_EQUAL(s->vptr, "A\xc3\xa9\xd2\xaf", 5);

  // Surrogate pair
  n = parse(pool, "{\"s\":\"\\uD834\\uDD1E\"}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/s", &s), 0);
  IW_TEST_ASSERT_EQUAL(s->vsize, 4);
  IW_TEST_ASSERT_NSTR_EQUAL(s->vptr, "\xf0\x9d\x84\x9e", 4);

  // An unknown escape sequence is kept as is (the backslash is not dropped)
  n = parse(pool, "{\"s\":\"\\q\"}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/s", &s), 0);
  IW_TEST_ASSERT_STR_EQUAL(s->vptr, "\\q");

  // Empty string
  n = parse(pool, "{\"s\":\"\"}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/s", &s), 0);
  IW_TEST_ASSERT_EQUAL(s->vsize, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL(s->vptr);

  // Escaped keys
  n = parse(pool, "{\"a\\\"b\":1,\"c\\u0041\":2}");
  struct jbl_node *k;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/a\"b", &k), 0);
  IW_TEST_ASSERT_EQUAL(k->vi64, 1);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/cA", &k), 0);
  IW_TEST_ASSERT_EQUAL(k->vi64, 2);

  iwpool_destroy(pool);
}

//--- Parsing: errors

static void iwjser_test1_parse_errors(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct jbl_node *n = (void*) 1;
  iwrc rc;

  rc = jbn_from_json("{\"a\":}", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(n);

  rc = jbn_from_json("{", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(n);

  rc = jbn_from_json("[1,", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(n);

  rc = jbn_from_json("{\"a\" 1}", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("{\"a\"::1}", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("{a:1}", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("'a'", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("\"unterminated", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_UNQUOTED_STRING);
  IW_TEST_ASSERT_PTR_NULL_FATAL(n);

  rc = jbn_from_json("\"\\uZZZZ\"", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_INVALID_CODEPOINT);
  IW_TEST_ASSERT_PTR_NULL_FATAL(n);

  // A high surrogate not followed by a low one
  rc = jbn_from_json("\"\\uD834\"", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_INVALID_CODEPOINT);

  rc = jbn_from_json("\"\\uD834\\u0041\"", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_INVALID_CODEPOINT);

  rc = jbn_from_json("{\"a\":tru}", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("{\"a\":nul}", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(n);

  // Only whitespace may follow the document
  rc = jbn_from_json("{\"a\":1} {\"b\":2}", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(n);

  rc = jbn_from_json("[1] x", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("1 2", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_js("{a:1} ]", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);

  rc = jbn_from_json("  {\"a\":1}  \n\t ", &n, pool);
  IW_TEST_ASSERT_EQUAL(rc, 0);

  // A tree allocated without a pool is released on a parse error
  struct jbl_node *mp = (void*) 1;
  rc = jbn_from_json("{\"a\":[1,2,{]}", &mp, 0);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(mp);

  rc = jbn_from_json("{\"a\":}", &mp, 0);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(mp);

  rc = jbn_from_js("{a:[1,}", &mp, 0);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(mp);

  // A parsed key that was not consumed by a value node
  rc = jbn_from_json("{\"a\":]}", &mp, 0);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(mp);

  rc = jbn_from_json("{\"a\":,}", &mp, 0);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL_FATAL(mp);

  // Maximal nesting level
  {
    char buf[1024];
    int len = 0;
    memset(buf, '[', sizeof(buf));
    len = BINN_MAX_NESTING_LEVELS + 2;
    IW_TEST_ASSERT_TRUE_FATAL(len < (int) sizeof(buf));
    for (int i = 0; i < len; ++i) {
      buf[i] = '[';
    }
    buf[len] = '\0';
    rc = jbn_from_json(buf, &n, pool);
    IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED);
  }

  iwpool_destroy(pool);
}

//--- Parsing: BOM, numbers, js literals

static void iwjser_test1_numbers(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  // UTF-8 BOM is skipped
  struct jbl_node *n = parse(pool, "\xEF\xBB\xBF{\"a\":1}");
  struct jbl_node *v;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/a", &v), 0);
  IW_TEST_ASSERT_EQUAL(v->type, JBV_I64);
  IW_TEST_ASSERT_EQUAL(v->vi64, 1);

  struct {
    const char *json;
    jbl_type_t  type;
    int64_t     i;
    double      d;
  } cases[] = {
    { "0", JBV_I64, 0, 0 },
    { "-0", JBV_I64, 0, 0 },
    { "123", JBV_I64, 123, 0 },
    { "-123", JBV_I64, -123, 0 },
    { "9223372036854775807", JBV_I64, 9223372036854775807LL, 0 },
    { "-9223372036854775807", JBV_I64, -9223372036854775807LL, 0 },
    { "1.5", JBV_F64, 0, 1.5 },
    { "-1.5", JBV_F64, 0, -1.5 },
    { "0.25", JBV_F64, 0, 0.25 },
    { "1e3", JBV_F64, 0, 1000.0 },
    { "1E-2", JBV_F64, 0, 0.01 },
    { "-2.5e2", JBV_F64, 0, -250.0 },
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json(cases[i].json, &n, pool), 0);
    IW_TEST_ASSERT_EQUAL(n->type, cases[i].type);
    if (cases[i].type == JBV_I64) {
      IW_TEST_ASSERT_EQUAL(n->vi64, cases[i].i);
    } else {
      IW_TEST_ASSERT_DOUBLE_EQUAL(n->vf64, cases[i].d, 0.000001);
    }
  }

  // Numbers nested into a container
  n = parse(pool, "{\"a\":[1,-2.5,true,false,null]}");
  char *out = print(n, 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"a\":[1,-2.5,true,false,null]}");
  free(out);

  iwpool_destroy(pool);
}

static void iwjser_test1_js(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *n = 0;
  iwrc rc = jbn_from_js("{a:1,'b':2,\"d\":'x',e:{f:[]},g:null}", &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  char *out = print(n, 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"a\":1,\"b\":2,\"d\":\"x\",\"e\":{\"f\":[]},\"g\":null}");
  free(out);

  // JS string values may use single quotes
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_js("\"a\"", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_js("'a'", &n, pool), 0);
  IW_TEST_ASSERT_STR_EQUAL(n->vptr, "a");

  // Malformed js object
  IW_TEST_ASSERT_EQUAL(jbn_from_js("{a}", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_js("{a:}", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_js("{'a:1}", &n, pool), JBL_ERROR_PARSE_JSON);

  iwpool_destroy(pool);
}

//--- iwjson_ftoa

static void iwjser_test1_ftoa(void) {
  char buf[IWNUMBUF_SIZE];
  size_t len;

  iwjson_ftoa(1.5, buf, &len);
  IW_TEST_ASSERT_EQUAL(len, strlen(buf));
  IW_TEST_ASSERT_STR_EQUAL(buf, "1.5");

  iwjson_ftoa(2.0, buf, &len);
  IW_TEST_ASSERT_EQUAL(len, strlen(buf));
  IW_TEST_ASSERT_STR_EQUAL(buf, "2");

  iwjson_ftoa(0.0, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "0");

  iwjson_ftoa(-1.25, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "-1.25");

  iwjson_ftoa(100.0, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "100");

  iwjson_ftoa(-0.5, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "-0.5");
  IW_TEST_ASSERT_EQUAL(len, 4);

  iwjson_ftoa(123456.75, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "123456.75");
}

//--- Printing

static iwrc _failing_printer(const char *data, int size, char ch, int count, void *op) {
  (void) data;
  (void) size;
  (void) ch;
  (void) count;
  (void) op;
  return IW_ERROR_FAIL;
}

static void iwjser_test1_printers(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct iwxstr *xstr = iwxstr_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(xstr);

  struct jbl_node *n = parse(pool, "{\"a\":[1,2.5,true,false,null],\"s\":\"str\"}");
  char *out = print(n, 0);

  // Count printer
  int cnt = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json(n, jbl_count_json_printer, &cnt, 0), 0);
  IW_TEST_ASSERT_EQUAL(cnt, (int) strlen(out));

  // XSTR printer
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json(n, jbl_xstr_json_printer, xstr, 0), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), out);

  // Direct printer calls
  iwxstr_clear(xstr);
  IW_TEST_ASSERT_EQUAL(jbl_xstr_json_printer("ab", -1, 0, 0, xstr), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "ab");
  iwxstr_clear(xstr);
  IW_TEST_ASSERT_EQUAL(jbl_xstr_json_printer("ab", 1, 0, 0, xstr), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "a");
  iwxstr_clear(xstr);
  IW_TEST_ASSERT_EQUAL(jbl_xstr_json_printer("ab", 2, 0, 3, xstr), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "ababab");
  iwxstr_clear(xstr);
  IW_TEST_ASSERT_EQUAL(jbl_xstr_json_printer(0, 0, 'x', 4, xstr), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "xxxx");
  IW_TEST_ASSERT_EQUAL(jbl_xstr_json_printer(0, 0, 'x', 1, 0), IW_ERROR_INVALID_ARGS);

  // FSTREAM printer
  FILE *f = tmpfile();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(f);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json(n, jbl_fstream_json_printer, f, 0), 0);
  fflush(f);
  IW_TEST_ASSERT_EQUAL(ftell(f), (long) strlen(out));
  rewind(f);
  char rbuf[256];
  size_t rsz = fread(rbuf, 1, sizeof(rbuf) - 1, f);
  IW_TEST_ASSERT_TRUE(rsz > 0);
  rbuf[rsz] = '\0';
  IW_TEST_ASSERT_STR_EQUAL(rbuf, out);
  fclose(f);
  IW_TEST_ASSERT_EQUAL(jbl_fstream_json_printer("ab", 2, 0, 1, 0), IW_ERROR_INVALID_ARGS);

  // A very large count must not overflow the stack
  f = tmpfile();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(f);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_fstream_json_printer(0, 0, 'x', 100000, f), 0);
  fflush(f);
  IW_TEST_ASSERT_EQUAL(ftell(f), 100000);
  fclose(f);

  // Printer errors are propagated
  IW_TEST_ASSERT_EQUAL(jbn_as_json(n, _failing_printer, 0, 0), IW_ERROR_FAIL);

  free(out);
  iwxstr_destroy(xstr);
  iwpool_destroy(pool);
}

static void iwjser_test1_print_escapes(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *root = parse(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(
    jbn_add_item_str(root, "s", "a\"b\\c\b\f\n\r\t", -1, 0, pool), 0);
  char *out = print(root, 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"s\":\"a\\\"b\\\\c\\b\\f\\n\\r\\t\"}");
  free(out);

  // Control characters must produce a valid JSON text
  struct jbl_node *ctrl = parse(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(ctrl, "s", "\x01\x07\x0b\x1f", 4, 0, pool), 0);
  out = print(ctrl, 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"s\":\"\\u0001\\u0007\\u000B\\u001F\"}");
  free(out);

  // Codepoints mode
  struct jbl_node *cp = parse(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(cp, "s", "\xc3\xa9\xf0\x9d\x84\x9e\x01", -1, 0, pool), 0);
  out = print(cp, JBL_PRINT_CODEPOINTS);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"s\":\"\\u00E9\\uD834\\uDD1E\\u0001\"}");
  free(out);

  // Without codepoints the utf8 bytes are passed through
  out = print(cp, 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"s\":\"\xc3\xa9\xf0\x9d\x84\x9e\\u0001\"}");
  free(out);

  // Invalid utf8 is reported in codepoints mode
  struct jbl_node *bad = parse(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(bad, "s", "\xff", 1, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL(jbn_as_json(bad, jbl_count_json_printer, &(int){0}, JBL_PRINT_CODEPOINTS),
                       JBL_ERROR_PARSE_INVALID_UTF8);

  // Escaped keys as well
  struct jbl_node *keys = parse(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(keys, "k\"\n", "v", -1, 0, pool), 0);
  out = print(keys, 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"k\\\"\\n\":\"v\"}");
  free(out);

  iwpool_destroy(pool);
}

static void iwjser_test1_pretty(void) {
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);

  struct jbl_node *n = parse(pool, "{\"a\":{\"b\":[1,2]},\"c\":[],\"d\":{}}");
  char *out = print(n, JBL_PRINT_PRETTY | JBL_PRINT_PRETTY_INDENT2);
  IW_TEST_ASSERT_STR_EQUAL(
    out,
    "{\n"
    "  \"a\": {\n"
    "    \"b\": [\n"
    "      1,\n"
    "      2\n"
    "    ]\n"
    "  },\n"
    "  \"c\": [],\n"
    "  \"d\": {}\n"
    "}");
  free(out);

  iwpool_destroy(pool);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwjser_test1_escapes),
  IW_TEST_CASE(iwjser_test1_parse_errors),
  IW_TEST_CASE(iwjser_test1_numbers),
  IW_TEST_CASE(iwjser_test1_js),
  IW_TEST_CASE(iwjser_test1_ftoa),
  IW_TEST_CASE(iwjser_test1_printers),
  IW_TEST_CASE(iwjser_test1_print_escapes),
  IW_TEST_CASE(iwjser_test1_pretty),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwjser_test1", cases, init_suite, 0));
}
