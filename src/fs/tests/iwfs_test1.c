// clang-format off
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2017 Softmotions Ltd <info@softmotions.com>
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
// clang-format on

#include "iowow.h"
#include "log/iwlog.h"
#include "fs/iwexfile.h"
#include "utils/iwutils.h"

#include "iwcfg.h"
#include <CUnit/Basic.h>
#include <locale.h>

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

int clean_suite(void) { return 0; }

void iwfs_exfile_test1(void) {
  iwrc rc = 0;
  IWFS_EXT ef;

  const char *path = "iwfs_exfile_test1.dat";
  IWFS_EXT_OPTS opts = {.file = {.path = path,
                                 .lock_mode = IWP_WLOCK,
                                 .omode = IWFS_DEFAULT_OMODE | IWFS_OTRUNC},
                        .use_locks = 1};
  IWRC(iwfs_exfile_open(&ef, &opts), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  char data[] = "b069a540-bc92-49ba-95e9-d1a2ee9e8c8f";
  size_t sp, sp2;

  // iwrc(*write)(struct IWFS_EXT* f, off_t off, const void *buf, size_t siz,
  // size_t *sp);
  IWRC(ef.write(&ef, 0, 0, 0, &sp), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(sp, 0);

  IWRC(ef.write(&ef, 1, 0, 0, &sp), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  IWP_FILE_STAT fstat;
  IWRC(iwp_fstat(path, &fstat), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(sp, 0);
  CU_ASSERT_EQUAL(fstat.size, iwp_page_size());

  IWRC(ef.write(&ef, 1, data, sizeof(data), &sp), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(sp, 37);

  IWRC(ef.close(&ef), rc);
  CU_ASSERT_EQUAL(rc, 0);

  // Now reopen the file

  opts.file.omode = IWFS_OREAD;
  IWRC(iwfs_exfile_open(&ef, &opts), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  char rdata[37];
  // iwrc(*read)(struct IWFS_EXT* f, off_t off, void *buf, size_t siz, size_t
  // *sp);
  IWRC(ef.read(&ef, 1, rdata, sp, &sp2), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(sp, sp2);
  CU_ASSERT_FALSE(strncmp(rdata, data, sizeof(data)));

  rc = ef.write(&ef, 1, data, sizeof(data), &sp);
  CU_ASSERT_EQUAL(IW_ERROR_READONLY, rc);

  size_t ps = iwp_page_size();
  rc = 0;
  IWRC(ef.read(&ef, ps - 1, rdata, 2, &sp2), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(sp2, 1);

  IWRC(ef.close(&ef), rc);
  CU_ASSERT_EQUAL(rc, 0);
}

void test_fibo_inc(void) {
  const char *path = "test_fibo_inc.dat";
  IWFS_EXT ef;
  IWFS_EXT_OPTS opts = {.file = {.path = path,
                                 .lock_mode = IWP_WLOCK,
                                 .omode = IWFS_DEFAULT_OMODE | IWFS_OTRUNC},
                        .use_locks = 0,
                        .rspolicy = iw_exfile_szpolicy_fibo};
  iwrc rc = 0;
  size_t sp;
  uint64_t wd = (uint64_t)(-1);

  IWRC(iwfs_exfile_open(&ef, &opts), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // iwrc(*write)(struct IWFS_EXT* f, off_t off, const void *buf, size_t siz,
  // size_t *sp);
  IWRC(ef.write(&ef, 0, &wd, 1, &sp), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  size_t psize = iwp_page_size();
  IWP_FILE_STAT fstat;
  IWRC(iwp_fstat(path, &fstat), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(fstat.size, psize);

  IWRC(ef.write(&ef, fstat.size, &wd, 1, &sp), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  IWRC(iwp_fstat(path, &fstat), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(fstat.size, 2 * psize);

  IWRC(ef.write(&ef, fstat.size, &wd, 1, &sp), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  IWRC(iwp_fstat(path, &fstat), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(fstat.size, 3 * psize);

  IWRC(ef.write(&ef, fstat.size, &wd, 1, &sp), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  IWRC(iwp_fstat(path, &fstat), rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(fstat.size, 5 * psize);

  IWRC(ef.close(&ef), rc);
  CU_ASSERT_EQUAL(rc, 0);
}

void test_mmap1(void) {
  iwrc rc = 0;
  size_t psize = iwp_page_size();
  size_t sp;
  const int dsize = psize * 4;
  uint8_t *data = malloc(dsize);
  uint8_t *cdata = malloc(dsize);

  const char *path = "test_mmap1.dat";
  IWFS_EXT ef;
  IWFS_EXT_OPTS opts = {.file = {.path = path, .omode = IWFS_OTRUNC},
                        .use_locks = 0};

  for (int i = 0; i < dsize; ++i) {
    data[i] = iwu_rand(256);
  }
  rc = iwfs_exfile_open(&ef, &opts);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // iwrc(*add_mmap)(struct IWFS_EXT* f, off_t off, size_t maxlen);
  rc = ef.add_mmap(&ef, 2 * psize, psize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = ef.add_mmap(&ef, psize, psize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = ef.add_mmap(&ef, 0, psize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = ef.add_mmap(&ef, psize, 2 * psize);
  CU_ASSERT_EQUAL_FATAL(rc, IWFS_ERROR_MMAP_OVERLAP);

  rc = ef.add_mmap(&ef, 3 * psize, UINT64_MAX);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // iwrc(*write)(struct IWFS_EXT* f, off_t off, const void *buf, size_t siz,
  // size_t *sp);
  rc = ef.write(&ef, psize / 2, data, psize, &sp);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(sp, psize);

  rc = ef.read(&ef, psize / 2, cdata, psize, &sp);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(sp, psize);
  CU_ASSERT_EQUAL_FATAL(memcmp(data, cdata, psize), 0);

  for (int i = 0; i < dsize; ++i) {
    data[i] = iwu_rand(256);
  }

  // iwrc(*remove_mmap)(struct IWFS_EXT* f, off_t off);
  rc = ef.remove_mmap(&ef, psize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = ef.write(&ef, psize / 2, data, psize, &sp);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(psize, sp);

  rc = ef.read(&ef, psize / 2, cdata, psize, &sp);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(psize, sp);
  CU_ASSERT_EQUAL_FATAL(memcmp(data, cdata, psize), 0);

  for (int i = 0; i < 10; ++i) {
    rc = ef.write(&ef, psize * i, data, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);

    rc = ef.read(&ef, psize * i, cdata, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);
    CU_ASSERT_EQUAL_FATAL(memcmp(data, cdata, psize), 0);
  }

  for (int i = 0; i < dsize; ++i) {
    data[i] = iwu_rand(256);
  }

  rc = ef.remove_mmap(&ef, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 10; ++i) {
    rc = ef.write(&ef, psize * i, data, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);

    rc = ef.read(&ef, psize * i, cdata, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);
    CU_ASSERT_EQUAL_FATAL(memcmp(data, cdata, psize), 0);
  }

  for (int i = 0; i < dsize; ++i) {
    data[i] = iwu_rand(256);
  }
  rc = ef.remove_mmap(&ef, 2 * psize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 10; ++i) {
    rc = ef.write(&ef, psize * i, data, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);

    rc = ef.read(&ef, psize * i, cdata, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);
    CU_ASSERT_EQUAL_FATAL(memcmp(data, cdata, psize), 0);
  }

  for (int i = 0; i < dsize; ++i) {
    data[i] = iwu_rand(256);
  }
  rc = ef.remove_mmap(&ef, 3 * psize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 10; ++i) {
    rc = ef.write(&ef, psize * i, data, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);

    rc = ef.read(&ef, psize * i, cdata, dsize, &sp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(dsize, sp);
    CU_ASSERT_EQUAL_FATAL(memcmp(data, cdata, psize), 0);
  }

  IWRC(ef.close(&ef), rc);
  CU_ASSERT_EQUAL(rc, 0);

  free(data);
  free(cdata);
}

int main() {
  setlocale(LC_ALL, "en_US.UTF-8");
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwfs_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "iwfs_exfile_test1", iwfs_exfile_test1)) ||
      (NULL == CU_add_test(pSuite, "test_fibo_inc", test_fibo_inc)) ||
      (NULL == CU_add_test(pSuite, "test_mmap1", test_mmap1))) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
