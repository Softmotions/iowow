//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2026 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *************************************************************************************************/


#include "iwcfg.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "iwtests.h"

#include "iwlog.h"
#include "iwutils.h"

int init_suite(void) {
  int rc = iwlog_init();
  return rc;
}

void iwlog_test1(void) {
  uint32_t ec = (0xfffffffdU & 0x3fffffffU);
  uint64_t rc = 0xfafafafaULL;
  rc = iwrc_set_errno(rc, ec);
  uint32_t ec2 = iwrc_strip_errno(&rc);
  IW_TEST_ASSERT_EQUAL(ec, ec2);
  IW_TEST_ASSERT_EQUAL(rc, 0xfafafafaULL);
}

void iwlog_test2(void) {
  IWLOG_DEFAULT_OPTS opts = { 0 };
  int rv = 0;
  size_t sz;
  char fname[] = "iwlog_test1_XXXXXX";
  int fd = mkstemp(fname);
  IW_TEST_ASSERT_TRUE(fd != 1);
  FILE *out = fdopen(fd, "w");
  IW_TEST_ASSERT_PTR_NOT_NULL(out);

  fprintf(stderr, "Redirecting log to: %s" IW_LINE_SEP, fname);

  opts.out = out;
  iwlog_set_logfn(0, &opts);

  iwlog_info2("7fa79c75beac413d83f35ffb6bf571b9");
  iwlog_error("7e94f7214af64513b30ab4df3f62714a%s", "C");
  iwlog_ecode_warn(IW_ERROR_READONLY, "c94645c3b107433497ef295b1c00dcff%d", 12);

  errno = ENOENT;
  iwrc ecode = iwrc_set_errno(IW_ERROR_ERRNO, errno);
  rv = iwlog(IWLOG_DEBUG, ecode, NULL, 0, "ERRNO Message");
  IW_TEST_ASSERT_EQUAL(rv, 0);
  errno = 0;
  fclose(out);

  out = fopen(fname, "r");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(out);

  char buf[1024];
  memset(buf, 0, 1024);
  sz = fread(buf, 1, 1024, out);
  IW_TEST_ASSERT_TRUE(sz);
  fprintf(stderr, "%s\n\n" IW_LINE_SEP, buf);

  IW_TEST_ASSERT_PTR_NOT_NULL(strstr(buf, "7fa79c75beac413d83f35ffb6bf571b9"));
  IW_TEST_ASSERT_PTR_NOT_NULL(strstr(buf, "7e94f7214af64513b30ab4df3f62714aC"));
  IW_TEST_ASSERT_PTR_NOT_NULL(strstr(buf,
                                "DEBUG 70001|2|0|Error with expected errno "
                                "status set. (IW_ERROR_ERRNO)|"));
  IW_TEST_ASSERT_PTR_NOT_NULL(strstr(buf, "ERRNO Message"));
  IW_TEST_ASSERT_PTR_NOT_NULL(strstr(buf, "ERROR iwlog_test1.c:"));

  IW_TEST_ASSERT_PTR_NOT_NULL(strstr(buf, "70005|0|0|Resource is readonly. (IW_ERROR_READONLY)|"));
  IW_TEST_ASSERT_PTR_NOT_NULL(strstr(buf, "c94645c3b107433497ef295b1c00dcff12"));

  fclose(out);
  unlink(fname);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwlog_test1),
  IW_TEST_CASE(iwlog_test2),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwlog_test1", cases, init_suite, 0));
}

