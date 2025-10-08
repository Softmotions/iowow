#pragma once
#ifndef IWTP_H
#define IWTP_H

/**************************************************************************************************
 * Threads pool.
 *
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2024 Softmotions Ltd <info@softmotions.com>
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
#include <pthread.h>

IW_EXTERN_C_START;

struct iwtp;
typedef struct iwtp*IWTP;

struct iwtp_spec {
  /** Optional thread name prefix in thread pool.
   * @note Thread name length must be not greater then 15 characters.
   */
  const char *thread_name_prefix;

  /** Number of hot threads in thread pool.
   * Threads are allocated on when thread pool created.
   * @note Value must be in rage [1-1024].
   * @note If zero then value will be set to number of cpu cores.
   */
  int num_threads;

  /** Maximum number of tasks in queue.
     Zero for unlimited queue. */
  int queue_limit;

  /** If task queue is full and the `overflow_threads_factor` is not zero
   * then pool is allowed to spawn extra threads to process tasks as long
   * as overall number of threads less of equal to `num_threads + num_threads * overflow_threads_factor`
   * @note Max: 2
   */
  int overflow_threads_factor;

  /**
   * It true performs log warning in the case of spawning overflow thread.
   */
  bool warn_on_overflow_thread_spawn;

  /**
   * Optional thread initializer function called when pool thread is created.
   */
  void (*thread_initializer)(pthread_t);
};

/**
 * @brief Task to execute
 */
typedef void (*iwtp_task_f)(void *arg);

/**
 * @brief Creates a new thread pool instance using provided `spec` config.
 */
IW_EXPORT iwrc iwtp_start_by_spec(const struct iwtp_spec *spec, struct iwtp **out_tp);

/**
 * @brief Creates a new thread pool instance.
 * @param num_threads Number of threads in the pool, accepted values in range `[1-1024]`
 * @param queue_limit Maximum number of tasks in queue. Zero for unlimited queue.
 * @param [out] out_tp Holder for thread pool instance.
 */
IW_EXPORT iwrc iwtp_start(const char *thread_name_prefix, int num_threads, int queue_limit, struct iwtp **out_tp);

/**
 * @brief Submits new task into thread pool.
 * @note `IW_ERROR_INVALID_STATE` if called after `iwtp_shutdown()`.
 * @note `IW_ERROR_OVERFLOW` if size of tasks queue reached `queue_limit`.
 * @param tp Pool instance
 * @param task Task function
 * @param task_arg Argument for task function
 */
IW_EXPORT iwrc iwtp_schedule(struct iwtp *tp, iwtp_task_f task, void *task_arg);

/**
 * @brief Shutdowns thread pool and disposes all nresources.
 * @note Function will wait until current task completes or
 * wait for all enqueued tasks if `wait_for_all` is set to `true`.
 * No new tasks will be accepted during `iwstw_shutdown` call.

 * @param tpp Pointer to pool which should be disposed.
 * @param wait_for_all If true worker will wait for completion of all enqueued tasks before shutdown.
 */
IW_EXPORT iwrc iwtp_shutdown(struct iwtp **tpp, bool wait_for_all);

/**
 * @brief Returns size of tasks queue.
 */
IW_EXPORT int iwtp_queue_size(struct iwtp *tp);

/**
 * @brief Returns number of threads currently executing tasks.
 */
IW_EXPORT  int iwtp_threads_busy_num(struct iwtp *tp);

IW_EXTERN_C_END;
#endif
