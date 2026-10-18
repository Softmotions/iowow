// JSON text parser and serializer primitives tests.
#include "iwlog.h"
#include "iwxstr.h"
#include "iwutils.h"
#include "iwpool.h"
#include "iwconv.h"

#include "iwjson.h"

#include <ctype.h>
#include <math.h>
#ifdef __APPLE__
#include <xlocale.h>
#else
#include <locale.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <float.h>
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

  // JSON numbers are decimal only: no hex, no leading zeroes
  IW_TEST_ASSERT_EQUAL(jbn_from_json("0x1A", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_json("0123", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_json("-0123", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_json("{\"a\":00}", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_json("{\"a\":0x1A}", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_json(".5", &n, pool), JBL_ERROR_PARSE_JSON);

  // The js-like parser keeps hexadecimal and legacy octal literals
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_js("{a:0x1A,b:0123,c:.5,d:-.5}", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/a", &v), 0);
  IW_TEST_ASSERT_EQUAL(v->vi64, 26);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/b", &v), 0);
  IW_TEST_ASSERT_EQUAL(v->vi64, 83);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/c", &v), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(v->vf64, 0.5, 0.00001);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(n, "/d", &v), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(v->vf64, -0.5, 0.00001);

  // An integer which does not fit into int64_t becomes a floating point value
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("9223372036854775808", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(n->vf64, 9223372036854775808.0, 1.0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("-9223372036854775809", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(n->vf64, -9223372036854775809.0, 2048.0);
  IW_TEST_ASSERT_EQUAL(jbn_from_json("1e400", &n, pool), JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_EQUAL(jbn_from_json("{\"a\":1e999}", &n, pool), JBL_ERROR_PARSE_JSON);

  // Subnormal values are parsed and printed without loss
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("4.9406564584124654e-324", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(n->vf64, 5e-324, 0.0);
  char *sub = print(n, 0);
  IW_TEST_ASSERT_STR_EQUAL(sub, "4.94065645841247e-324");
  free(sub);

  // Underflow is converted to zero
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("1e-400", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(n->vf64, 0.0, 0.0);

  // Small values keep their precision
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("1e-9", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_F64);
  IW_TEST_ASSERT_DOUBLE_EQUAL(n->vf64, 1e-9, 1e-21);
  char *small = print(n, 0);
  IW_TEST_ASSERT_STR_EQUAL(small, "1e-09");
  free(small);

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

  // Moderate magnitudes use the plain decimal notation
  iwjson_ftoa(0.000006, buf, &len);
  IW_TEST_ASSERT_EQUAL(len, strlen(buf));
  IW_TEST_ASSERT_STR_EQUAL(buf, "0.000006");
  iwjson_ftoa(0.000001, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "0.000001");
  iwjson_ftoa(1e-8, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "0.00000001");
  iwjson_ftoa(1.5e-8, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "0.000000015");
  iwjson_ftoa(1e15, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "1000000000000000");
  iwjson_ftoa(1e16, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "1e+16");

  // Values which need more than 8 fractional digits are not truncated
  iwjson_ftoa(1e-9, buf, &len);
  IW_TEST_ASSERT_EQUAL(len, strlen(buf));
  IW_TEST_ASSERT_STR_EQUAL(buf, "1e-09");

  iwjson_ftoa(0.1 + 0.2, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "0.30000000000000004");

  iwjson_ftoa(DBL_MAX, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "1.7976931348623157e+308");

  // 16 significant digits are not always enough to restore a double
  iwjson_ftoa(3.2175151490036762e+209, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "3.2175151490036762e+209");
  iwjson_ftoa(7.1989792719134434e+87, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "7.1989792719134434e+87");

  // Subnormal values
  iwjson_ftoa(5e-324, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "4.94065645841247e-324");

  // Every produced value is converted back to the same number
  const long double vals[] = { 0.1L, 1e-9L, 3.14159265358979323846L, 1e300L, -1e-300L, 12345.6789L };
  for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); ++i) {
    iwjson_ftoa(vals[i], buf, &len);
    IW_TEST_ASSERT_EQUAL(len, strlen(buf));
    IW_TEST_ASSERT_TRUE_FATAL(strtold(buf, 0) == vals[i]);
  }

  // JSON has no non finite numbers
  iwjson_ftoa(NAN, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "null");
  IW_TEST_ASSERT_EQUAL(len, 4);
  iwjson_ftoa(INFINITY, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "null");
  iwjson_ftoa(-INFINITY, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "null");
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

  // Non finite numbers are printed as JSON null
  struct jbl_node *fin = parse(pool, "{}");
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_f64(fin, "nan", NAN, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_f64(fin, "inf", INFINITY, 0, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_f64(fin, "ninf", -INFINITY, 0, pool), 0);
  free(out);
  out = print(fin, 0);
  IW_TEST_ASSERT_STR_EQUAL(out, "{\"nan\":null,\"inf\":null,\"ninf\":null}");

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


//--- JSON number syntax audit

/**
 * Checks that `s` matches the RFC 8259 number grammar:
 *   number = [ "-" ] int [ frac ] [ exp ]
 *   int    = "0" / (digit1-9 *DIGIT)
 *   frac   = "." 1*DIGIT
 *   exp    = ("e" / "E") [ "-" / "+" ] 1*DIGIT
 */
static bool _is_json_number(const char *s) {
  if (!s || !*s) {
    return false;
  }
  if (*s == '-') {
    ++s;
  }
  if (*s == '0') {
    ++s;
    if ((*s >= '0') && (*s <= '9')) {
      return false; // Leading zero
    }
  } else if ((*s >= '1') && (*s <= '9')) {
    while ((*s >= '0') && (*s <= '9')) {
      ++s;
    }
  } else {
    return false;
  }
  if (*s == '.') {
    ++s;
    if (!((*s >= '0') && (*s <= '9'))) {
      return false;
    }
    while ((*s >= '0') && (*s <= '9')) {
      ++s;
    }
  }
  if ((*s == 'e') || (*s == 'E')) {
    ++s;
    if ((*s == '+') || (*s == '-')) {
      ++s;
    }
    if (!((*s >= '0') && (*s <= '9'))) {
      return false;
    }
    while ((*s >= '0') && (*s <= '9')) {
      ++s;
    }
  }
  return *s == '\0';
}

/**
 * Validates every number literal of the JSON text `json`.
 *
 * @return Number of the checked number literals, or -1 if an invalid number literal is found.
 */
static int _check_json_numbers(const char *json) {
  int numbers = 0;
  const char *p = json;
  while (*p) {
    if (*p == '"') { // Skip a string literal
      ++p;
      while (*p && (*p != '"')) {
        if ((*p == '\\') && *(p + 1)) {
          p += 2;
          continue;
        }
        ++p;
      }
      if (*p != '"') {
        return -1;
      }
      ++p;
      continue;
    }
    if ((*p == '-') || ((*p >= '0') && (*p <= '9'))) {
      const char *start = p;
      while (*p && (*p != ',') && (*p != ']') && (*p != '}') && !isspace((unsigned char) *p)) {
        ++p;
      }
      char tok[64];
      size_t len = (size_t) (p - start);
      if (len >= sizeof(tok)) {
        return -1;
      }
      memcpy(tok, start, len);
      tok[len] = '\0';
      if (!_is_json_number(tok)) {
        return -1;
      }
      ++numbers;
      continue;
    }
    ++p;
  }
  return numbers;
}

static void iwjser_test1_number_syntax(void) {
  char buf[IWNUMBUF_SIZE];
  size_t len;

  // (1) iwjson_ftoa(): every produced text is a valid JSON number which restores the value
  IW_TEST_ASSERT_TRUE_FATAL(_is_json_number("0"));
  IW_TEST_ASSERT_TRUE_FATAL(_is_json_number("-0"));
  IW_TEST_ASSERT_TRUE_FATAL(_is_json_number("1e+16"));
  IW_TEST_ASSERT_FALSE(_is_json_number("01"));
  IW_TEST_ASSERT_FALSE(_is_json_number("+1"));
  IW_TEST_ASSERT_FALSE(_is_json_number(".5"));
  IW_TEST_ASSERT_FALSE(_is_json_number("1."));
  IW_TEST_ASSERT_FALSE(_is_json_number("1e"));
  IW_TEST_ASSERT_FALSE(_is_json_number("nan"));
  IW_TEST_ASSERT_FALSE(_is_json_number("inf"));
  IW_TEST_ASSERT_FALSE(_is_json_number("1,5"));

  uint64_t state = 0x243F6A8885A308D3ULL; // Deterministic xorshift, stable test runs
  int checked = 0, nonfinite = 0;
  for (int i = 0; i < 100000; ++i) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    double d;
    memcpy(&d, &state, sizeof(d));
    iwjson_ftoa(d, buf, &len);
    IW_TEST_ASSERT_EQUAL(len, strlen(buf));
    if (isnan(d) || isinf(d)) {
      IW_TEST_ASSERT_STR_EQUAL(buf, "null");
      ++nonfinite;
      continue;
    }
    IW_TEST_ASSERT_TRUE_FATAL(_is_json_number(buf));
    char *ep = 0;
    double rv = strtod(buf, &ep);
    IW_TEST_ASSERT_TRUE_FATAL(ep && (ep != buf) && (*ep == '\0'));
    IW_TEST_ASSERT_TRUE_FATAL(rv == d); // The text restores the exact value
    ++checked;
  }
  IW_TEST_ASSERT_TRUE(checked > 90000);
  IW_TEST_ASSERT_TRUE(nonfinite > 0);

  // (2) The DOM printer: all int64 edge values and the double corner cases
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct jbl_node *doc = parse(pool, "{}");
  static const int64_t ivals[] = {
    0, 1, -1, 42, -42, INT64_MAX, INT64_MIN, INT64_MAX - 1, INT64_MIN + 1,
    1000000000000000000LL, -1000000000000000000LL
  };
  char key[32];
  for (size_t i = 0; i < sizeof(ivals) / sizeof(ivals[0]); ++i) {
    snprintf(key, sizeof(key), "i%zu", i);
    IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_i64(doc, key, ivals[i], 0, pool), 0);
  }
  // Note: integral doubles are printed without a fraction (JSON has no int/float distinction)
  static const double dvals[] = {
    0.5, -0.5, 1.0 / 3.0, 0.1 + 0.2, 1e-9, 1e-300, 1e300, -1e300,
    DBL_MAX, -DBL_MAX, DBL_MIN, 5e-324, 1e16, 1e15, -0.0
  };
  for (size_t i = 0; i < sizeof(dvals) / sizeof(dvals[0]); ++i) {
    snprintf(key, sizeof(key), "d%zu", i);
    IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_f64(doc, key, dvals[i], 0, pool), 0);
  }
  // Strings containing digits must not confuse the number scanner
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_add_item_str(doc, "s", "12abc -3.5e+2", -1, 0, pool), 0);

  char *out = print(doc, 0);
  IW_TEST_ASSERT_EQUAL(_check_json_numbers(out),
                       (int) (sizeof(ivals) / sizeof(ivals[0]) + sizeof(dvals) / sizeof(dvals[0])));
  free(out);
  out = print(doc, JBL_PRINT_PRETTY_INDENT2);
  IW_TEST_ASSERT_EQUAL(_check_json_numbers(out),
                       (int) (sizeof(ivals) / sizeof(ivals[0]) + sizeof(dvals) / sizeof(dvals[0])));
  free(out);

  // The printed numbers are parsed back to the same values,
  // except the integral doubles which become integers and NaN/Inf which are not used here
  out = print(doc, 0);
  struct jbl_node *back = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json(out, &back, pool), 0);
  struct jbl_node *v1, *v2;
  for (size_t i = 0; i < sizeof(ivals) / sizeof(ivals[0]); ++i) {
    snprintf(key, sizeof(key), "/i%zu", i);
    IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(doc, key, &v1), 0);
    IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(back, key, &v2), 0);
    IW_TEST_ASSERT_EQUAL(v2->type, JBV_I64);
    IW_TEST_ASSERT_EQUAL(v2->vi64, v1->vi64);
  }
  // Doubles keep the fractional part and the exponent notation
  static const char *dfkeys[] = { "/d0", "/d1", "/d2", "/d3", "/d4", "/d5", "/d6", "/d7", "/d8", "/d9", "/d10", "/d11", "/d12" };
  for (size_t i = 0; i < sizeof(dfkeys) / sizeof(dfkeys[0]); ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(doc, dfkeys[i], &v1), 0);
    IW_TEST_ASSERT_EQUAL_FATAL(jbn_at(back, dfkeys[i], &v2), 0);
    IW_TEST_ASSERT_EQUAL(v2->type, JBV_F64);
    IW_TEST_ASSERT_DOUBLE_EQUAL(v2->vf64, v1->vf64, 0.0);
  }
  free(out);

  // (3) The binary document printer over all binn numeric types.
  // Note: the unsigned binn types are printed through the signed int64_t JSON number model.
  struct jbl *jbl = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_create_empty_object(&jbl), 0);
  struct binn bv = BINN_INITIALIZER;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_int64(jbl, "i64min", INT64_MIN), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_int64(jbl, "i64max", INT64_MAX), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_int64(jbl, "i8", -128), 0);
  IW_TEST_ASSERT_TRUE_FATAL(binn_create_u64c(&bv, 42));
  IW_TEST_ASSERT_TRUE_FATAL(binn_add_keyed(&jbl->bn, "u8", *binnv(&bv)));
  binn_destroy(&bv);
  IW_TEST_ASSERT_TRUE_FATAL(binn_create_u64c(&bv, 70000));
  IW_TEST_ASSERT_TRUE_FATAL(binn_add_keyed(&jbl->bn, "u32", *binnv(&bv)));
  binn_destroy(&bv);
  IW_TEST_ASSERT_TRUE_FATAL(binn_create_u64c(&bv, UINT64_MAX));
  IW_TEST_ASSERT_TRUE_FATAL(binn_add_keyed(&jbl->bn, "u64max", *binnv(&bv)));
  binn_destroy(&bv);
  IW_TEST_ASSERT_TRUE_FATAL(binn_create_f32c(&bv, 1.5f));
  IW_TEST_ASSERT_TRUE_FATAL(binn_add_keyed(&jbl->bn, "f32", *binnv(&bv)));
  binn_destroy(&bv);
  IW_TEST_ASSERT_TRUE_FATAL(binn_create_f64c(&bv, -1e300));
  IW_TEST_ASSERT_TRUE_FATAL(binn_add_keyed(&jbl->bn, "f64", *binnv(&bv)));
  binn_destroy(&bv);
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_set_string(jbl, "s", "1e5"), 0);

  out = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_as_json_alloc(jbl, 0, &out), 0);
  IW_TEST_ASSERT_EQUAL(_check_json_numbers(out), 8);
  free(out);
  out = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbl_as_json_alloc(jbl, JBL_PRINT_PRETTY, &out), 0);
  IW_TEST_ASSERT_EQUAL(_check_json_numbers(out), 8);
  free(out);
  jbl_destroy(&jbl);

  iwpool_destroy(pool);
}


//--- Locale independence

/** Returns the name of an installed locale with a comma decimal separator, or zero. */
static const char* _comma_locale(void) {
  static const char *names[] = {
    "de_DE.UTF-8", "de_DE.utf8", "fr_FR.UTF-8", "fr_FR.utf8",
    "ru_RU.UTF-8", "ru_RU.utf8", "es_ES.UTF-8", "es_ES.utf8",
    "it_IT.UTF-8", "it_IT.utf8", "pt_BR.UTF-8", "pt_BR.utf8"
  };
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
#ifdef _WIN32
    _locale_t cl = _create_locale(LC_NUMERIC, names[i]);
    if (cl) {
      _free_locale(cl);
      return names[i];
    }
#else
    locale_t cl = newlocale(LC_NUMERIC_MASK, names[i], (locale_t) 0);
    if (cl) {
      freelocale(cl);
      return names[i];
    }
#endif
  }
  return 0;
}

// JSON numbers always use `.` as the decimal separator regardless of LC_NUMERIC
static void iwjser_test1_locale(void) {
  const char *name = _comma_locale();
  if (!name) {
    IW_TEST_SKIP("no installed locale with a comma decimal separator");
    return;
  }
  char saved[64], saved_dp[16];
  const char *saved_locale = setlocale(LC_NUMERIC, 0);
  snprintf(saved, sizeof(saved), "%s", saved_locale ? saved_locale : "C");
  snprintf(saved_dp, sizeof(saved_dp), "%s", localeconv()->decimal_point);
  if (!setlocale(LC_NUMERIC, name) || strcmp(localeconv()->decimal_point, ",") != 0) {
    setlocale(LC_NUMERIC, saved);
    IW_TEST_SKIP("cannot switch to a locale with a comma decimal separator");
    return;
  }

  // Only non fatal assertions below: the process locale must be restored on any outcome
  char buf[IWNUMBUF_SIZE];
  size_t len;
  iwjson_ftoa(1.5, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "1.5");
  iwjson_ftoa(0.000006, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "0.000006");
  iwjson_ftoa(1e-9, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "1e-09");
  iwjson_ftoa(-1234.25, buf, &len);
  IW_TEST_ASSERT_STR_EQUAL(buf, "-1234.25");

  iwrc rc = 0;
  IW_TEST_ASSERT_DOUBLE_EQUAL(iw_strtod("2.5", &rc), 2.5, 0.0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  rc = 0;
  IW_TEST_ASSERT_DOUBLE_EQUAL((double) iw_strtold("2.5", &rc), 2.5, 0.0);
  IW_TEST_ASSERT_EQUAL(rc, 0);

  // Parsing is locale independent
  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *n = 0;
  IW_TEST_ASSERT_EQUAL(jbn_from_json("{\"a\":1.5,\"b\":[0.25,1e-9]}", &n, pool), 0);
  if (n) {
    char *out = 0;
    IW_TEST_ASSERT_EQUAL(jbn_as_json_alloc(n, 0, &out), 0);
    IW_TEST_ASSERT_STR_EQUAL(out, "{\"a\":1.5,\"b\":[0.25,1e-09]}");
    free(out);
  }
  // A comma decimal separator is not a valid JSON number in any locale
  IW_TEST_ASSERT_EQUAL(jbn_from_json("{\"a\":1,5}", &n, pool), JBL_ERROR_PARSE_JSON);

  struct jbl *jbl = 0;
  IW_TEST_ASSERT_EQUAL(jbl_from_json(&jbl, "{\"d\":2.5,\"e\":-0.125}"), 0);
  if (jbl) {
    double fv = 0;
    IW_TEST_ASSERT_EQUAL(jbl_object_get_f64(jbl, "d", &fv), 0);
    IW_TEST_ASSERT_DOUBLE_EQUAL(fv, 2.5, 0.0);
    char *out = 0;
    IW_TEST_ASSERT_EQUAL(jbl_as_json_alloc(jbl, 0, &out), 0);
    IW_TEST_ASSERT_STR_EQUAL(out, "{\"d\":2.5,\"e\":-0.125}");
    free(out);
    jbl_destroy(&jbl);
  }
  iwpool_destroy(pool);

  // The process locale is restored
  setlocale(LC_NUMERIC, saved);
  IW_TEST_ASSERT_STR_EQUAL(localeconv()->decimal_point, saved_dp);
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
  IW_TEST_CASE(iwjser_test1_number_syntax),
  IW_TEST_CASE(iwjser_test1_locale),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwjser_test1", cases, init_suite, 0));
}
