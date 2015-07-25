#include "iwcfg.h"
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <CUnit/Basic.h>
#include "log/iwlog.h"


int init_suite(void) {
    return 0;
}

int clean_suite(void) {
    return 0;
}

void iwlog_test1() {
    IWLOG_DEFAULT_OPTS opts = {0};
    int rv = 0;
    char fname[] = "iwlog_test1_XXXXXX";
    int fd = mkstemp(fname);
    CU_ASSERT_TRUE(fd != 1);
    FILE *out = fdopen(fd, "w");
    CU_ASSERT_PTR_NOT_NULL(out);

    fprintf(stderr, "Redirecting log to: %s" IW_LINE_SEP, fname);

    opts.out = out;
    iwlog_set_logfn_opts(&opts);

    iwlog_info2("7fa79c75beac413d83f35ffb6bf571b9");
    iwlog_error("7e94f7214af64513b30ab4df3f62714a%s", "C");

    errno = ENOENT;
    rv = iwlog(IWLOG_DEBUG, 0, NULL, 0, "ERRNO Message");
    CU_ASSERT_EQUAL(rv, 0);
    errno = 0;
    fclose(out);

    out = fopen(fname, "r");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);

    char buf[1024];
    memset(buf, 0, 1024);
    fread(buf, 1, 1024, out);
    fprintf(stderr, "%s" IW_LINE_SEP, buf);

    CU_ASSERT_PTR_NOT_NULL(strstr(buf, "7fa79c75beac413d83f35ffb6bf571b9"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buf, "7e94f7214af64513b30ab4df3f62714aC"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buf, "DEBUG 0|2|0||"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buf, "ERRNO Message"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buf, "ERROR iwlog_test1.c:"));

    fclose(out);
    unlink(fname);
}

int main() {
    setlocale(LC_ALL, "en_US.UTF-8");
    CU_pSuite pSuite = NULL;

    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* Add a suite to the registry */
    pSuite = CU_add_suite("iwlog_test1", init_suite, clean_suite);

    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "iwlog_test1", iwlog_test1))
       ) {
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
