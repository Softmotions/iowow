#pragma once
#ifndef IWSTW_H
#define IWSTW_H

/**************************************************************************************************
 * Single thread worker.
 *
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
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

#include "basedefs.h"

IW_EXTERN_C_START

struct _IWSTW;
typedef struct _IWSTW*IWSTW;

/**
 * @brief Task to execute
 */
typedef void (*iwstw_task_f)(void *arg);

/**
 * @brief Starts a single thread worker.
 *        Function will block until start of worker thread.
 *
 * @param queue_limit Max length of pending tasks queue. Unlimited if zero.
 * @param queue_blocking If true iwstw_schedule will block when queue reached its limit.
 * @param[out] stwp_out Pointer to worker handler to be initialized.
 */
IW_EXPORT iwrc iwstw_start(const char *thread_name, int queue_limit, bool queue_blocking, IWSTW *out_stw);

/**
 * @brief Shutdowns worker and disposes all resources.
 *        Function will wait until current task completes or
 *        wait for all enqueued tasks if `wait_for_all` is set to `true`.
 *        No new tasks will be accepted during `iwstw_shutdown` call.
 *
 * @param stw Pointer to worker handler which should be destroyed.
 * @param wait_for_all If true worker will wait for completion of all enqueued tasks before shutdown.
 */
IW_EXPORT iwrc iwstw_shutdown(IWSTW *stwp, bool wait_for_all);

/**
 * @brief Schedule task for execution.
 *        Task will be added to pending tasks queue.
 *
 * @note If tasks queue is reached its length limit
 *        current thread will be blocked if `queue_blocking` is true
 *        or `IW_ERROR_OVERFLOW` will be returned.
 * @note If worker is in process of stopping `IW_ERROR_INVALID_STATE` will be returned.
 */
IW_EXPORT iwrc iwstw_schedule(IWSTW stw, iwstw_task_f task, void *task_arg);

/**
 * @brief Schedule task only if task queue is empty.
 */
IW_EXPORT iwrc iwstw_schedule_empty_only(IWSTW stw, iwstw_task_f task, void *task_arg, bool *out_scheduled);

/**
 * @brief Returns size of tasks queue.
 */
IW_EXPORT int iwstw_queue_size(IWSTW stw);

IW_EXTERN_C_END
#endif
