#include "iowow.h"
#include "log/iwlog.h"
#include "fs/iwexfile.h"


#include "iwcfg.h"
#include <CUnit/Basic.h>
#include <locale.h>

int init_suite(void) {
    int rc = iw_init();
    return rc;
}

int clean_suite(void) {
    return 0;
}

void iwfs_exfile_test1(void) {
    iwrc rc = 0;
    IWFS_EXFILE ef;

    const char *path = "iwfs_exfile_test1.dat";
    IWFS_EXFILE_OPTS opts = {
        .fopts = {
            .path = path,
            .lock_mode = IWP_WLOCK,
            .open_mode = IWFS_DEFAULT_OMODE | IWFS_OTRUNC
        },
        .use_locks = 1
    };
    IWRC(iwfs_exfile_open(&ef, &opts), rc);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    char data[] = "b069a540-bc92-49ba-95e9-d1a2ee9e8c8f";
    size_t sp, sp2;

    //iwrc(*write)(struct IWFS_EXFILE* f, off_t off, const void *buf, size_t siz, size_t *sp);
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

    //Now reopen the file

    opts.fopts.open_mode = IWFS_OREAD;
    IWRC(iwfs_exfile_open(&ef, &opts), rc);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    char rdata[37];
    //iwrc(*read)(struct IWFS_EXFILE* f, off_t off, void *buf, size_t siz, size_t *sp);
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

int main() {
    setlocale(LC_ALL, "en_US.UTF-8");
    CU_pSuite pSuite = NULL;

    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* Add a suite to the registry */
    pSuite = CU_add_suite("iwfs_test1", init_suite, clean_suite);

    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */
    if (
        (NULL == CU_add_test(pSuite, "iwfs_exfile_test1", iwfs_exfile_test1))
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
