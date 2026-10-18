#pragma once
#ifndef IWJSREG_H
#define IWJSREG_H

/**************************************************************************************************
 * IWOWOW A simple JSON registry stored in single file supporting atomic updates.
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

/**
 * @file iwjsreg.h
 * @brief JSON registry stored in a single file with support of atomic updates.
 *
 * The registry keeps a JSON object (`struct jbl_node` DOM tree, see @ref iwjbn.h) in memory and
 * persists it to a file. Every modification is applied under the write lock of the registry and is
 * either synchronized explicitly by `iwjsreg_sync()` or automatically, if the `IWJSREG_AUTOSYNC`
 * flag is set.
 *
 * File updates are atomic: the new document is written to the `<path>.tmp` file first, flushed and
 * then renamed over the original file, so a reader never observes a partially written document.
 *
 * Locking can be provided either by an external `pthread_rwlock_t` (`iwjsreg_spec::rwl`) which is
 * shared between all registry instances of the same file, or by a set of user supplied
 * lock/unlock functions (`iwjsreg_spec::wlock_fn`, `iwjsreg_spec::rlock_fn`,
 * `iwjsreg_spec::unlock_fn`).
 *
 * Example:
 * @code
 * struct iwjsreg *reg;
 * iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = "/tmp/registry.json" }, &reg);
 * if (rc) { ... }
 * rc = iwjsreg_set_str(reg, "name", "John");
 * iwjsreg_close(&reg);
 * @endcode
 *
 * @see iwjbn.h, iwjson.h
 */

#include "basedefs.h"
#include "iwjson.h"
#include <pthread.h>

IW_EXTERN_C_START;

/** Store the registry file in the compact binary `binn` format instead of JSON text. */
#define IWJSREG_FORMAT_BINARY 0x01U
/** Synchronize the registry file automatically after every modification. */
#define IWJSREG_AUTOSYNC      0x02U
/**
 * Open the registry in the read-only mode: no modifications and no file writes are allowed.
 * Modification functions return `IW_ERROR_READONLY` for such a registry.
 */
#define IWJSREG_READONLY      0x04U

/** @brief JSON registry instance. */
struct iwjsreg;

/**
 * @brief JSON registry open specification.
 */
struct iwjsreg_spec {
  const char       *path;        /**< Path to the registry file. Required. */
  pthread_rwlock_t *rwl;         /**< Optional RWL provided for locking. */
  iwrc     (*wlock_fn)(void*);   /**< Optional exclusive write lock function to set read/write registry lock. */
  iwrc     (*rlock_fn)(void*);   /**< Optional shared read lock function to set the lock. */
  iwrc     (*unlock_fn)(void*);  /**< Optional unlock function releasing the lock. */
  void    *fn_data;              /**< Arbitrary user data used in wlock_fn,rlock_fn,unlock_fn. */
  unsigned flags;                /**< Bitmask of `IWJSREG_*` flags. */
};

/**
 * @brief Opens (or creates) the JSON registry file.
 *
 * If the file does not exist, an empty registry object is created.
 *
 * @param spec  Registry open specification. Not zero.
 * @param [out] out Holder of the opened registry. Not zero.
 * @return Zero on success.
 *
 * @see iwjsreg_close()
 */
IW_EXPORT iwrc iwjsreg_open(struct iwjsreg_spec *spec, struct iwjsreg **out);

/**
 * @brief Synchronizes the registry with its file (if it was modified), releases the registry and
 *        sets `regp` to zero.
 *
 * Synchronization is skipped for the read-only registries.
 *
 * @param regp Holder of the registry instance. Not zero.
 */
IW_EXPORT iwrc iwjsreg_close(struct iwjsreg** regp);

/**
 * @brief Writes the current registry state into the registry file.
 *
 * Does nothing for a read-only registry or if the registry has no modifications.
 *
 * @param reg Registry instance. Not zero.
 */
IW_EXPORT iwrc iwjsreg_sync(struct iwjsreg* reg);

/**
 * @brief Removes the top level property `key` from the registry.
 *
 * @param reg Registry instance. Not zero.
 * @param key Property name. Not zero.
 */
IW_EXPORT iwrc iwjsreg_remove(struct iwjsreg* reg, const char *key);

/**
 * @brief Sets the top level string property `key`.
 *
 * @param reg   Registry instance. Not zero.
 * @param key   Property name. Not zero.
 * @param value Property value. Not zero.
 */
IW_EXPORT iwrc iwjsreg_set_str(struct iwjsreg* reg, const char *key, const char *value);

/**
 * @brief Sets the top level integer property `key`.
 *
 * @param reg   Registry instance. Not zero.
 * @param key   Property name. Not zero.
 * @param value Property value.
 */
IW_EXPORT iwrc iwjsreg_set_i64(struct iwjsreg* reg, const char *key, int64_t value);

/**
 * @brief Increments the top level integer property `key`.
 *
 * A missing property is treated as zero.
 *
 * @param reg Registry instance. Not zero.
 * @param key Property name. Not zero.
 * @param inc Increment value.
 * @param [out] out Holder of the resulting value. Optional.
 */
IW_EXPORT iwrc iwjsreg_inc_i64(struct iwjsreg* reg, const char *key, int64_t inc, int64_t *out);

/**
 * @brief Sets the top level boolean property `key`.
 *
 * @param reg   Registry instance. Not zero.
 * @param key   Property name. Not zero.
 * @param value Property value.
 */
IW_EXPORT iwrc iwjsreg_set_bool(struct iwjsreg *reg, const char *key, bool value);

/**
 * @brief Reads the top level property `key` as a string.
 *
 * Scalars are converted to their JSON text form.
 *
 * @param reg Registry instance. Not zero.
 * @param key Property name. Not zero.
 * @param [out] out Holder of the allocated string, should be released by `free()`. Not zero.
 */
IW_EXPORT iwrc iwjsreg_get_str(struct iwjsreg* reg, const char *key, char **out);

/**
 * @brief Reads the top level integer property `key`.
 *
 * @param reg Registry instance. Not zero.
 * @param key Property name. Not zero.
 * @param [out] out Value holder. Not zero.
 */
IW_EXPORT iwrc iwjsreg_get_i64(struct iwjsreg* reg, const char *key, int64_t *out);

/**
 * @brief Reads the top level boolean property `key`.
 *
 * @param reg Registry instance. Not zero.
 * @param key Property name. Not zero.
 * @param [out] out Value holder. Not zero.
 */
IW_EXPORT iwrc iwjsreg_get_bool(struct iwjsreg* reg, const char *key, bool *out);

/**
 * @brief Clones the registry subtree pointed by `path` into a new JSON DOM tree.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer of the copied subtree. If zero the whole registry root is cloned.
 * @param pool Memory pool used for the cloned tree allocations. Optional.
 * @param [out] out Holder of the cloned tree. Not zero.
 */
IW_EXPORT iwrc iwjsreg_copy(struct iwjsreg* reg, const char *path, struct iwpool *pool, struct jbl_node **out);

/**
 * @brief Applies the JSON Merge Patch `json` at the `path` of the registry.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer of the merge target.
 * @param json Merge patch value. Not zero.
 *
 * @see iwjsreg_replace()
 */
IW_EXPORT iwrc iwjsreg_merge(struct iwjsreg* reg, const char *path, struct jbl_node *json);

/**
 * @brief Same as iwjsreg_merge() but for a string value.
 *
 * @param reg   Registry instance. Not zero.
 * @param path  rfc6901 JSON pointer of the merge target.
 * @param value String value. Not zero.
 * @param len   Value length in bytes, or a negative value to use `strlen(value)`.
 */
IW_EXPORT iwrc iwjsreg_merge_str(struct iwjsreg* reg, const char *path, const char *value, int len);

/**
 * @brief Same as iwjsreg_merge() but for an integer value.
 *
 * @param reg   Registry instance. Not zero.
 * @param path  rfc6901 JSON pointer of the merge target.
 * @param value Integer value.
 */
IW_EXPORT iwrc iwjsreg_merge_i64(struct iwjsreg *reg, const char *path, int64_t value);

/**
 * @brief Same as iwjsreg_merge() but for a floating point value.
 *
 * @param reg   Registry instance. Not zero.
 * @param path  rfc6901 JSON pointer of the merge target.
 * @param value Floating point value.
 */
IW_EXPORT iwrc iwjsreg_merge_f64(struct iwjsreg *reg, const char *path, double value);

/**
 * @brief Same as iwjsreg_merge() but for a boolean value.
 *
 * @param reg   Registry instance. Not zero.
 * @param path  rfc6901 JSON pointer of the merge target.
 * @param value Boolean value.
 */
IW_EXPORT iwrc iwjsreg_merge_bool(struct iwjsreg *reg, const char *path, bool value);

/**
 * @brief Removes the value at `path` by applying a `null` JSON Merge Patch value.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer to remove.
 */
IW_EXPORT iwrc iwjsreg_merge_remove(struct iwjsreg *reg, const char *path);

/**
 * @brief Replaces the whole subtree at `path` by `json`.
 *
 * Unlike iwjsreg_merge() the existing subtree is removed first, so the resulting subtree contains
 * exactly the `json` content.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer of the replaced subtree.
 * @param json Replacement value. Not zero.
 */
IW_EXPORT iwrc iwjsreg_replace(struct iwjsreg* reg, const char *path, struct jbl_node *json);

/**
 * @brief Reads the integer value pointed by `path`.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer. Not zero.
 * @param [out] out Value holder. Not zero.
 */
IW_EXPORT iwrc iwjsreg_at_i64(struct iwjsreg* reg, const char *path, int64_t *out);

/**
 * @brief Reads the floating point value pointed by `path`.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer. Not zero.
 * @param [out] out Value holder. Not zero.
 */
IW_EXPORT iwrc iwjsreg_at_f64(struct iwjsreg* reg, const char *path, double *out);

/**
 * @brief Reads the boolean value pointed by `path`.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer. Not zero.
 * @param [out] out Value holder. Not zero.
 */
IW_EXPORT iwrc iwjsreg_at_bool(struct iwjsreg* reg, const char *path, bool *out);

/**
 * @brief Reads the value pointed by `path` as a string.
 *
 * Scalars are converted to their JSON text form.
 *
 * @param reg  Registry instance. Not zero.
 * @param path rfc6901 JSON pointer. Not zero.
 * @param [out] out Holder of the allocated string, should be released by `free()`. Not zero.
 */
IW_EXPORT iwrc iwjsreg_at_str(struct iwjsreg* reg, const char *path, char **out);

IW_EXTERN_C_END;

#endif
