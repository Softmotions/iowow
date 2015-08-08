/**************************************************************************************************
 *  IOWOW library
 *  Copyright (C) 2012-2015 Softmotions Ltd <info@softmotions.com>
 *
 *  This file is part of IOWOW.
 *  IOWOW is free software; you can redistribute it and/or modify it under the terms of
 *  the GNU Lesser General Public License as published by the Free Software Foundation; either
 *  version 2.1 of the License or any later version. IOWOW is distributed in the hope
 *  that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *  You should have received a copy of the GNU Lesser General Public License along with IOWOW;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 *  Boston, MA 02111-1307 USA.
 *************************************************************************************************/

#include "iowow.h"
#include "log/iwlog.h"
#include "fs/iwfsmfile.h"
#include "utils/iwutils.h"

#include "iwcfg.h"
#include <CUnit/Basic.h>
#include <locale.h>
#include <unistd.h>
#include <pthread.h>

typedef struct _FSMREC {
    uint64_t offset;
    int64_t length;
    int locked;
    struct _FSMREC *prev;
    struct _FSMREC *next;
} FSMREC;

static pthread_mutex_t records_mtx;

int init_suite(void) {
    unlink("test_fsm_open_close.fsm");
    pthread_mutex_init(&records_mtx, 0);
    int rc = iw_init();
    return rc;
}

int clean_suite(void) {
    pthread_mutex_destroy(&records_mtx);
    return 0;
}

uint64_t iwfs_fsmdbg_number_of_free_areas(IWFS_FSM *f);
uint64_t iwfs_fsmdbg_find_next_set_bit(const uint64_t *addr, uint64_t offset_bit, uint64_t max_offset_bit, int *found);
uint64_t iwfs_fsmdbg_find_prev_set_bit(const uint64_t *addr, uint64_t offset_bit, uint64_t min_offset_bit, int *found);
void iwfs_fsmdbg_dump_fsm_tree(IWFS_FSM *f, const char *hdr);
iwrc iwfs_fsmdb_state(IWFS_FSM *f, IWFS_FSMDBG_STATE *d);

void test_fsm_bitmap(void) {
#define BMSZ1 16
    uint64_t buf[BMSZ1];
    memset(buf, 0, BMSZ1 * sizeof(uint64_t));
    int found = 0;

    uint64_t val = 0x3UL; /* 0000011 */
    uint64_t res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 0);

    res = iwfs_fsmdbg_find_next_set_bit(&val, 1, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 1);

    res = iwfs_fsmdbg_find_next_set_bit(&val, 2, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 0);
    CU_ASSERT_EQUAL(res, 0);

    val = 0x3UL << 2; /* 0001100 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    val = 0x3UL << 2; /* 0001100 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 2, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    val = 0x3UL << 2; /* 0001100 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 3, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 3);

    val = 0x3UL << 2; /* 0001100 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 4, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 0);
    CU_ASSERT_EQUAL(res, 0);

    val = 0x3UL << 2; /* 0001100 */
    res = iwfs_fsmdbg_find_prev_set_bit(&val, 2, 0, &found);
    CU_ASSERT_EQUAL(found, 0);
    CU_ASSERT_EQUAL(res, 0);

    val = 0x3UL << 2; /* 0001100 */
    res = iwfs_fsmdbg_find_prev_set_bit(&val, 3, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    val = 0x2UL; /* 00000010 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 1);

    val = 0x2UL; /* 00000010 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 1, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 1);

    val = 0x4UL; /* 00000100 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    val = 0x4UL; /* 00000100 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 1, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    val = 0x4UL; /* 00000100 */
    res = iwfs_fsmdbg_find_next_set_bit(&val, 2, sizeof(uint64_t) * 8, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    val = ~0UL;
    res = iwfs_fsmdbg_find_prev_set_bit(&val, 0, 0, &found);
    CU_ASSERT_EQUAL(found, 0);
    CU_ASSERT_EQUAL(res, 0);

    val = 0x1UL; /* 00000001 */
    res = iwfs_fsmdbg_find_prev_set_bit(&val, 1, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 0);

    val = 0x2UL; /* 00000010 */
    res = iwfs_fsmdbg_find_prev_set_bit(&val, 10, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 1);

    buf[0] = 0x1UL;
    res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 0);

    buf[0] = 0x2UL;
    res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 1);

    buf[0] = 0x4UL;
    res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    buf[0] = 0x8UL;
    res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 3);

    buf[1] = 0x2UL;
    res = iwfs_fsmdbg_find_prev_set_bit(buf, 2 * sizeof(uint64_t) * 8 + 17, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 64 + 1);

    /* 0[0100000000000..|00]000 */
    buf[0] = 0x4UL;
    buf[1] = 0x0UL;
    buf[2] = 0x0UL;
    res = iwfs_fsmdbg_find_prev_set_bit(buf, (sizeof(uint64_t) * 8 + 2), 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 2);

    buf[0] = 0x4UL;
    buf[1] = 0x4UL;
    buf[2] = 0x0UL;
    res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 5, 0, &found);
    CU_ASSERT_EQUAL(found, 1);
    CU_ASSERT_EQUAL(res, 64 + 2);

}

void test_fsm_open_close(void) {

    const int nblocks = 1024;
    const int dsize = (1 << 6) * nblocks + 1;
    unsigned char *data = malloc(dsize);
    unsigned char *rdata = malloc(dsize);
    int i;

    uint64_t oaddr, oaddr2;
    int64_t olen, olen2;
    int64_t sp;

    IWFS_FSM_OPTS opts = {
        .rwlfile = {
            .exfile = {
                .file = {
                    .path = "test_fsm_open_close.fsm",
                    .lock_mode = IWP_WLOCK
                },
                .rspolicy = iw_exfile_szpolicy_fibo,
                .initial_size = 0
            }
        },
        .bpow = 6,
        .hdrlen = 64,
        .oflags = IWFSM_STRICT
    };

}

int main() {
    setlocale(LC_ALL, "en_US.UTF-8");
    CU_pSuite pSuite = NULL;

    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* Add a suite to the registry */
    pSuite = CU_add_suite("iwfs_test2", init_suite, clean_suite);

    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */
    if (
        (NULL == CU_add_test(pSuite, "test_fsm_bitmap", test_fsm_bitmap)) ||
        (NULL == CU_add_test(pSuite, "test_fsm_open_close", test_fsm_open_close))
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
