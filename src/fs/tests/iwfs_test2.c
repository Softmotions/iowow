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

static pthread_mutex_t records_mtx;

int init_suite(void) {
    unlink("test_fsm_open_close.fsm");
    unlink("test_fsm_uniform_alloc.fsm");
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
iwrc iwfs_fsmdbg_state(IWFS_FSM *f, IWFS_FSMDBG_STATE *d);

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

    iwrc rc;
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

    size_t psize = iwp_page_size();
    IWFS_FSMDBG_STATE state1, state2;
    IWFS_FSM fsm;
    rc = iwfs_fsmfile_open(&fsm, &opts);
    CU_ASSERT_FALSE_FATAL(rc);
    rc = iwfs_fsmdbg_state(&fsm, &state1);
    CU_ASSERT_FALSE(rc);
    CU_ASSERT_TRUE((psize * 8 -  state1.lfbklen) * 64 == 2 * psize); //allocated first 2 pages
    rc = fsm.close(&fsm);
    CU_ASSERT_FALSE_FATAL(rc);

    rc = iwfs_fsmfile_open(&fsm, &opts);
    CU_ASSERT_FALSE_FATAL(rc);
    rc = iwfs_fsmdbg_state(&fsm, &state2);
    CU_ASSERT_FALSE(rc);
    CU_ASSERT_TRUE((psize * 8 -  state2.lfbklen) * 64 == 2 * psize);
    CU_ASSERT_EQUAL(state1.bmlen, state2.bmlen);
    CU_ASSERT_EQUAL(state1.bmoff, state2.bmoff);
    CU_ASSERT_EQUAL(state1.lfbklen, state2.lfbklen);
    CU_ASSERT_EQUAL(state1.lfbkoff, state2.lfbkoff);
    CU_ASSERT_EQUAL(state1.state.block_size, state2.state.block_size);
    CU_ASSERT_EQUAL(state1.state.blocks_num, state2.state.blocks_num);
    CU_ASSERT_EQUAL(state1.state.hdrlen, state2.state.hdrlen);
    CU_ASSERT_EQUAL(state1.state.oflags, state2.state.oflags);
    CU_ASSERT_EQUAL(state1.state.rwlfile.exfile.fsize, state2.state.rwlfile.exfile.fsize);
    CU_ASSERT_EQUAL(state1.state.rwlfile.exfile.fsize, 2 * psize);
    rc = fsm.close(&fsm);
    CU_ASSERT_FALSE_FATAL(rc);
}

//typedef struct _FSMREC {
//    uint64_t offset;
//    int64_t length;
//    int locked;
//    struct _FSMREC *prev;
//    struct _FSMREC *next;
//} FSMREC;

typedef struct {
    off_t addr;
    off_t len;
} ASLOT;

void test_fsm_uniform_alloc(void) {
    iwrc rc;
    IWFS_FSMDBG_STATE state1, state2;
    IWFS_FSM_OPTS opts = {
        .rwlfile = {
            .exfile = {
                .file = {
                    .path = "test_fsm_uniform_alloc.fsm",
                    .lock_mode = IWP_WLOCK,
                    .omode = IWFS_OTRUNC
                },
                .rspolicy = iw_exfile_szpolicy_fibo
            }
        },
        .bpow = 6,
        .hdrlen = 64,
        .oflags = IWFSM_STRICT
    };

    const int bsize = 512;
#define bcnt 4096
    ASLOT aslots[bcnt];

    IWFS_FSM fsm;
    rc = iwfs_fsmfile_open(&fsm, &opts);
    CU_ASSERT_FALSE_FATAL(rc);

    rc = iwfs_fsmdbg_state(&fsm, &state1);
    CU_ASSERT_FALSE_FATAL(rc);
    CU_ASSERT_EQUAL_FATAL(state1.state.rwlfile.exfile.file.ostatus, IWFS_OPEN_NEW);

    for (int i = 0; i < bcnt; ++i) {
        aslots[i].addr = 0;
        rc = fsm.allocate(&fsm, bsize, &aslots[i].addr, &aslots[i].len, 0);
        CU_ASSERT_FALSE_FATAL(rc);
    }
    rc = iwfs_fsmdbg_state(&fsm, &state1);
    CU_ASSERT_FALSE_FATAL(rc);

    if (iwp_page_size() == 4096) {
        CU_ASSERT_EQUAL(state1.bmlen, 8192);
        CU_ASSERT_EQUAL(state1.bmoff, 2097152);
        CU_ASSERT_EQUAL(state1.lfbklen, 32632);
        CU_ASSERT_EQUAL(state1.lfbkoff, 32904);
        CU_ASSERT_EQUAL(state1.state.blocks_num, 65536);
        CU_ASSERT_EQUAL(state1.state.free_segments_num, 2);
        CU_ASSERT_EQUAL(state1.state.avg_alloc_size, 8);
        CU_ASSERT_EQUAL(state1.state.alloc_dispersion, 0);
    }

    rc = fsm.close(&fsm);
    CU_ASSERT_FALSE_FATAL(rc);

    opts.rwlfile.exfile.file.omode = IWFS_OREAD;
    rc = iwfs_fsmfile_open(&fsm, &opts);
    CU_ASSERT_FALSE_FATAL(rc);

    rc = iwfs_fsmdbg_state(&fsm, &state2);
    CU_ASSERT_FALSE_FATAL(rc);
    CU_ASSERT_EQUAL_FATAL(state2.state.rwlfile.exfile.file.ostatus, IWFS_OPEN_EXISTING);
    CU_ASSERT_FALSE(state2.state.rwlfile.exfile.file.opts.omode & IWFS_OWRITE);

    CU_ASSERT_EQUAL(state1.bmlen, state2.bmlen);
    CU_ASSERT_EQUAL(state1.bmoff, state2.bmoff);
    CU_ASSERT_EQUAL(state1.lfbklen, state2.lfbklen);
    CU_ASSERT_EQUAL(state1.lfbkoff, state2.lfbkoff);
    CU_ASSERT_EQUAL(state1.state.blocks_num, state2.state.blocks_num);
    CU_ASSERT_EQUAL(state1.state.free_segments_num, state2.state.free_segments_num);
    CU_ASSERT_EQUAL(state1.state.avg_alloc_size, state2.state.avg_alloc_size);
    CU_ASSERT_EQUAL(state1.state.alloc_dispersion, state2.state.alloc_dispersion);

    uint32_t ibuf;
    off_t ilen;
    rc = fsm.allocate(&fsm, sizeof(ibuf), (void*)&ibuf, &ilen, 0);
    CU_ASSERT_EQUAL(rc, IW_ERROR_READONLY);

    rc = fsm.close(&fsm);
    CU_ASSERT_FALSE_FATAL(rc);

    opts.rwlfile.exfile.file.omode = IWFS_OWRITE;
    rc = iwfs_fsmfile_open(&fsm, &opts);
    CU_ASSERT_FALSE_FATAL(rc);

    rc = iwfs_fsmdbg_state(&fsm, &state1);
    CU_ASSERT_FALSE_FATAL(rc);

    if (iwp_page_size() == 4096) {
        CU_ASSERT_EQUAL(state1.bmlen, 8192);
        CU_ASSERT_EQUAL(state1.bmoff, 2097152);
        CU_ASSERT_EQUAL(state1.lfbklen, 32632);
        CU_ASSERT_EQUAL(state1.lfbkoff, 32904);
        CU_ASSERT_EQUAL(state1.state.blocks_num, 65536);
        CU_ASSERT_EQUAL(state1.state.free_segments_num, 2);
        CU_ASSERT_EQUAL(state1.state.avg_alloc_size, 8);
        CU_ASSERT_EQUAL(state1.state.alloc_dispersion, 0);
    }

    int i = 0;
    for (; i < bcnt; ++i) {
        rc = fsm.deallocate(&fsm, aslots[i].addr, aslots[i].len);
        CU_ASSERT_FALSE_FATAL(rc);
    }

//    4: FSM TREE: C1
//    4: [32896 32640]
//    4: [3 32765]

    iwfs_fsmdbg_dump_fsm_tree(&fsm, "C1");
    rc = fsm.close(&fsm);
    CU_ASSERT_FALSE_FATAL(rc);
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
        (NULL == CU_add_test(pSuite, "test_fsm_open_close", test_fsm_open_close)) ||
        (NULL == CU_add_test(pSuite, "test_fsm_uniform_alloc", test_fsm_uniform_alloc))
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
