#pragma once
#ifndef IWJBL_H
#define IWJBL_H

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

/**
 * @file iwjbl.h
 * @brief Memory compact binary ([Binn](https://github.com/liteserver/binn)) representation
 * of a JSON document.
 *
 * A `struct jbl` document keeps the JSON value in a compact serialized `binn` buffer. It is
 * efficient for storage and transport, supports incremental construction of objects/arrays and
 * in place serialization, but modification of an already built document is costly: JSON Patch and
 * JSON Merge Patch operations of this module convert the document into a `struct jbl_node` DOM tree
 * (see @ref iwjbn.h), modify it, and build a new `binn` buffer.
 *
 * @note This header includes `binnc.h` of the [binn-c](https://github.com/Softmotions/binn-c)
 *       library and thus it requires the `libbinnc` development files to be available.
 *
 * @see iwjbn.h, iwjson.h
 */

#include "iwjson.h"
#include "iwpool.h"

#include <binnc.h>
#include <stdarg.h>

IW_EXTERN_C_START;

/**
 * @brief JSON document in the memory compact binary [Binn](https://github.com/liteserver/binn) format.
 *
 * The `bn` member holds the serialized document and may be read directly by the `binn` API.
 * The `node` member caches an optional DOM tree associated with the document.
 */
struct jbl {
  struct binn      bn;   /**< Binn representation of the document. */
  struct jbl_node *node; /**< Cached DOM tree of the document. Optional. */
};

/**
 * @brief Empty `struct jbl` initializer.
 */
#define JBL_INITIALIZER { .bn = BINN_INITIALIZER }

//--- Construction

/**
 * @brief Creates an empty binary JSON object.
 *
 * @note `jblp` should be disposed of by `jbl_destroy()`.
 *
 * @param [out] jblp Holder of the created document. Not zero.
 */
IW_EXPORT iwrc jbl_create_empty_object(struct jbl **jblp);

/**
 * @brief Creates an empty binary JSON array.
 *
 * @note `jblp` should be disposed of by `jbl_destroy()`.
 *
 * @param [out] jblp Holder of the created document. Not zero.
 */
IW_EXPORT iwrc jbl_create_empty_array(struct jbl **jblp);

/**
 * @brief Creates a new `struct jbl` document by parsing the JSON text `jsonstr`.
 *
 * Any JSON value can be a document root, including scalars (`null`, booleans, numbers, strings).
 *
 * @note `jblp` should be disposed of by `jbl_destroy()`.
 *
 * @param [out] jblp  Holder of the created document. Not zero.
 * @param jsonstr     JSON text to parse. Not zero.
 */
IW_EXPORT iwrc jbl_from_json(struct jbl **jblp, const char *jsonstr);

/**
 * @brief Same as jbl_from_json() but takes a `printf()` style format string.
 */
IW_EXPORT iwrc jbl_from_json_printf(
  struct jbl **jblp, const char *format,
  ...) __attribute__((format(__printf__, 2, 3)));

/**
 * @brief `va_list` variant of jbl_from_json_printf().
 */
IW_EXPORT iwrc jbl_from_json_printf_va(struct jbl **jblp, const char *format, va_list va);

/**
 * @brief Initializes the `jbl` document from the serialized `binn` data in `buf`.
 *
 * @param jbl   Document to initialize. Not zero.
 * @param buf   Memory buffer holding serialized `binn` data. Not zero.
 * @param bufsz Size of `buf`.
 * @param wrap  If `true` the `buf` memory is wrapped and is not copied;
 *              the caller keeps the buffer ownership and must keep it alive while the document is used.
 */
IW_EXPORT iwrc jbl_init_from_buf(struct jbl *jbl, void *buf, size_t bufsz, bool wrap);

/**
 * @brief Same as jbl_init_from_buf() but allocates the `struct jbl` document with `malloc()`.
 *
 * @note `jblp` should be disposed of by `jbl_destroy()`.
 */
IW_EXPORT iwrc jbl_create_from_buf(struct jbl **jblp, void *buf, size_t bufsz, bool wrap);

/**
 * @brief Clones the `src` document into a newly allocated `targetp` document.
 *
 * @note `targetp` should be disposed of by `jbl_destroy()`.
 */
IW_EXPORT iwrc jbl_clone(const struct jbl *src, struct jbl **targetp);

/**
 * @brief Destroys the document and releases its heap resources.
 *
 * @note Sets `jblp` to zero.
 */
IW_EXPORT void jbl_destroy(struct jbl **jblp);

/**
 * @brief Releases the internal resources of `jbl`; the `struct jbl` itself is not freed.
 */
IW_EXPORT void jbl_reset(struct jbl *jbl);

//--- Value mutation

/**
 * @brief Sets an integer property value of the object document,
 *        or appends a value to the end of the array document.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl Document container. Not zero.
 * @param key Object key. Not used for array documents.
 * @param v   Value to set.
 */
IW_EXPORT iwrc jbl_set_int64(struct jbl *jbl, const char *key, int64_t v);

/**
 * @brief Sets a floating point property value of the object document,
 *        or appends a value to the end of the array document.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl Document container. Not zero.
 * @param key Object key. Not used for array documents.
 * @param v   Value to set.
 */
IW_EXPORT iwrc jbl_set_f64(struct jbl *jbl, const char *key, double v);

/**
 * @brief Sets a string property value of the object document,
 *        or appends a value to the end of the array document.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl Document container. Not zero.
 * @param key Object key. Not used for array documents.
 * @param v   Value to set. Not zero.
 */
IW_EXPORT iwrc jbl_set_string(struct jbl *jbl, const char *key, const char *v);

/**
 * @brief Same as jbl_set_string() but takes a `printf()` style format string.
 */
IW_EXPORT iwrc jbl_set_string_printf(
  struct jbl *jbl, const char *key, const char *format,
  ...) __attribute__((format(__printf__, 3, 4)));

/**
 * @brief Sets a boolean property value of the object document,
 *        or appends a value to the end of the array document.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl Document container. Not zero.
 * @param key Object key. Not used for array documents.
 * @param v   Value to set.
 */
IW_EXPORT iwrc jbl_set_bool(struct jbl *jbl, const char *key, bool v);

/**
 * @brief Sets a null property value of the object document,
 *        or appends a null to the end of the array document.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl Document container. Not zero.
 * @param key Object key. Not used for array documents.
 */
IW_EXPORT iwrc jbl_set_null(struct jbl *jbl, const char *key);

/**
 * @brief Sets an empty array property value of the object document,
 *        or appends an empty array to the end of the array document.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl Document container. Not zero.
 * @param key Object key. Not used for array documents.
 */
IW_EXPORT iwrc jbl_set_empty_array(struct jbl *jbl, const char *key);

/**
 * @brief Sets an empty object property value of the object document,
 *        or appends an empty object to the end of the array document.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl Document container. Not zero.
 * @param key Object key. Not used for array documents.
 */
IW_EXPORT iwrc jbl_set_empty_object(struct jbl *jbl, const char *key);

/**
 * @brief Sets a nested document property value of the object document,
 *        or appends a nested document to the end of the array document.
 *
 * The `nested` document data is copied, so `nested` may be destroyed after the call.
 *
 * @warning `jbl` must be writable, in other words created by
 *          `jbl_create_empty_object()` or `jbl_create_empty_array()`.
 *
 * @param jbl    Document container. Not zero.
 * @param key    Object key. Not used for array documents.
 * @param nested Nested document to add. Not zero.
 */
IW_EXPORT iwrc jbl_set_nested(struct jbl *jbl, const char *key, struct jbl *nested);

//--- Introspection

/**
 * @brief Returns the type of the `jbl` document value.
 */
IW_EXPORT jbl_type_t jbl_type(const struct jbl *jbl);

/**
 * @brief Returns the number of child elements of the `jbl` container, or zero.
 */
IW_EXPORT size_t jbl_count(const struct jbl *jbl);

/**
 * @brief Returns the size of the serialized `binn` representation of the `jbl` value in bytes.
 */
IW_EXPORT size_t jbl_size(const struct jbl *jbl);

/**
 * @brief Returns `sizeof(struct jbl)`.
 */
IW_EXPORT size_t jbl_structure_size(void);

/**
 * @brief Interprets the `jbl` value as `int32_t`.
 *
 * @return Zero if the value cannot be converted.
 */
IW_EXPORT int32_t jbl_get_i32(const struct jbl *jbl);

/**
 * @brief Interprets the `jbl` value as `int64_t`.
 *
 * @return Zero if the value cannot be converted.
 */
IW_EXPORT int64_t jbl_get_i64(const struct jbl *jbl);

/**
 * @brief Interprets the `jbl` value as `double`.
 *
 * @return Zero if the value cannot be converted.
 */
IW_EXPORT double jbl_get_f64(const struct jbl *jbl);

/**
 * @brief Interprets the `jbl` value as a `\0` terminated character array.
 *
 * @return Zero if the value cannot be converted.
 */
IW_EXPORT const char* jbl_get_str(const struct jbl *jbl);

/**
 * @brief Same as jbl_get_str() but also returns the string length.
 *
 * @param jbl         Document value. Not zero.
 * @param [out] out_len Holder of the value length in bytes. Optional.
 */
IW_EXPORT const char* jbl_get_str2(const struct jbl *jbl, size_t *out_len);

/**
 * @brief Same as jbl_get_str() but copies at most `bufsz` bytes into the target `buf`.
 *
 * The target buffer is not touched if the `jbl` value cannot be converted.
 *
 * @return Number of bytes copied.
 */
IW_EXPORT size_t jbl_copy_strn(const struct jbl *jbl, char *buf, size_t bufsz);

/**
 * @brief Returns the type of the object property `key`.
 *
 * @return Property type, or `JBV_NONE` if the property does not exist.
 */
IW_EXPORT jbl_type_t jbl_object_get_type(const struct jbl *jbl, const char *key);

/**
 * @brief Reads the integer object property `key`.
 *
 * @param jbl Document object. Not zero.
 * @param key Property name. Not zero.
 * @param [out] out Value holder. Not zero.
 * @return Zero on success, `JBL_ERROR_CREATION` if the property is missing or is not a number.
 */
IW_EXPORT iwrc jbl_object_get_i64(const struct jbl *jbl, const char *key, int64_t *out);

/**
 * @brief Reads the floating point object property `key`.
 *
 * @param jbl Document object. Not zero.
 * @param key Property name. Not zero.
 * @param [out] out Value holder. Not zero.
 * @return Zero on success, `JBL_ERROR_CREATION` if the property is missing or is not a number.
 */
IW_EXPORT iwrc jbl_object_get_f64(const struct jbl *jbl, const char *key, double *out);

/**
 * @brief Reads the boolean object property `key`.
 *
 * @return Zero on success, `JBL_ERROR_CREATION` if the property is missing or is not a boolean.
 */
IW_EXPORT iwrc jbl_object_get_bool(const struct jbl *jbl, const char *key, bool *out);

/**
 * @brief Returns a pointer to the string object property `key`.
 *
 * @return Zero on success, `JBL_ERROR_CREATION` if the property is missing or is not a string.
 */
IW_EXPORT iwrc jbl_object_get_str(const struct jbl *jbl, const char *key, const char **out);

/**
 * @brief Same as jbl_object_get_str() but also returns the value length.
 */
IW_EXPORT iwrc jbl_object_get_str2(const struct jbl *jbl, const char *key, const char **out, size_t *out_len);

/**
 * @brief Copies the object property `key` into the `out` document.
 *
 * @param jbl Document object. Not zero.
 * @param key Property name. Not zero.
 * @param out Initialized document holder. Not zero.
 * @return Zero on success, `JBL_ERROR_CREATION` if the property does not exist.
 */
IW_EXPORT iwrc jbl_object_get_jbl(const struct jbl *jbl, const char *key, struct jbl *out);

//--- Serialization

/**
 * @brief Returns the size in bytes of the serialized `binn` representation.
 */
IW_EXPORT size_t jbl_serialized_size(const struct jbl *jbl);

/**
 * @brief Serializes the document into the given buffer.
 *
 * @param jbl       Document to serialize. Not zero.
 * @param out_buf   Destination buffer. Not zero.
 * @param out_bufsz Size of the destination buffer.
 */
IW_EXPORT iwrc jbl_serialize_into(const struct jbl *jbl, uint8_t *out_buf, size_t out_bufsz);

/**
 * @brief Serializes the document feeding the `consumer` callback with the produced chunks.
 *
 * The final callback call is made with a zero `buf` and a zero `bufsz`. Serialization is aborted as
 * soon as `consumer` returns `false`.
 */
IW_EXPORT iwrc jbl_serialize(
  const struct jbl *jbl,
  bool (*consumer)(const uint8_t *buf, size_t bufsz, void *op),
  void *op);

/**
 * @brief Prints the document as JSON text.
 *
 * @param jbl Document to print. Not zero.
 * @param pt  JSON printer function. Not zero.
 * @param op  User data passed to the printer function.
 * @param pf  JSON printing mode flags.
 *
 * @see jbl_xstr_json_printer(), jbl_fstream_json_printer(), jbl_count_json_printer()
 */
IW_EXPORT iwrc jbl_as_json(const struct jbl *jbl, jbl_json_printer pt, void *op, jbl_print_flags_t pf);

/**
 * @brief Serializes the document into a newly allocated `\0` terminated C string.
 *
 * @param jbl     Document to print. Not zero.
 * @param pf      JSON printing mode flags.
 * @param [out] out Holder of the allocated string, should be released by `free()`. Not zero.
 */
IW_EXPORT iwrc jbl_as_json_alloc(const struct jbl *jbl, jbl_print_flags_t pf, char **out);

//--- JSON pointer

/**
 * @brief Finds the value of the document pointed by the rfc6901 `path`.
 *
 * @note `res` should be disposed of by `jbl_destroy()`.
 * @note If the value is not found `res` is set to zero.
 *
 * @param jbl       Document. Not zero.
 * @param path      rfc6901 JSON pointer. Not zero.
 * @param [out] res Output value holder. Not zero.
 */
IW_EXPORT iwrc jbl_at(const struct jbl *jbl, const char *path, struct jbl **res);

/**
 * @brief Same as jbl_at() but accepts a pre-parsed JSON pointer.
 *
 * @see jbl_ptr_alloc()
 */
IW_EXPORT iwrc jbl_at2(const struct jbl *jbl, struct jbl_ptr *jp, struct jbl **res);

//--- DOM tree conversion

/**
 * @brief Converts the `jbl` document into a `struct jbl_node` tree.
 *
 * @note `node` resources are released when `pool` is destroyed, or manually if `pool` is zero.
 *
 * @param jbl           Document. Not zero.
 * @param [out] node    Holder of the new tree. Not zero.
 * @param clone_strings If `true` JSON keys and string values are cloned into the given `pool`,
 *                      otherwise only pointers are assigned. Use `true` if the tree should outlive
 *                      or be independent of the `jbl` document.
 * @param pool          Memory pool used for the tree allocations. Optional.
 */
IW_EXPORT iwrc jbl_to_node(const struct jbl *jbl, struct jbl_node **node, bool clone_strings, struct iwpool *pool);

/**
 * @brief Fills the `jbl` document with data from the `node` tree.
 *
 * Common use case: create an empty document with `jbl_create_empty_object()` or
 * `jbl_create_empty_array()` and then fill it with `jbl_fill_from_node()`.
 *
 * @param jbl  Document to be filled. Not zero.
 * @param node Source tree node. Not zero.
 */
IW_EXPORT iwrc jbl_fill_from_node(struct jbl *jbl, const struct jbl_node *node);

/**
 * @brief Converts the `node` tree into a new `struct jbl` document.
 *
 * @note `jblp` should be disposed of by `jbl_destroy()`.
 *
 * @param [out] jblp Holder of the created document. Not zero.
 * @param node       Source tree node. The node must be an object or an array. Not zero.
 */
IW_EXPORT iwrc jbl_from_node(struct jbl **jblp, const struct jbl_node *node);

//--- Patching

/**
 * @brief Applies the JSON Patch `patch` (rfc6902) to the document.
 *
 * @param jbl   Target document. Not zero.
 * @param patch Array of patch operations. Not zero.
 * @param cnt   Number of patch operations.
 */
IW_EXPORT iwrc jbl_patch(struct jbl *jbl, const struct jbl_patch *patch, size_t cnt);

/**
 * @brief Applies the JSON Patch document `patchjson` to the document.
 *
 * If `patchjson` is a JSON array it is interpreted as a JSON Patch (rfc6902) document, if it is a
 * JSON object it is applied as a JSON Merge Patch (rfc7386) document.
 *
 * @param jbl       Target document. Not zero.
 * @param patchjson JSON Patch (array) or JSON Merge Patch (object) document text. Not zero.
 */
IW_EXPORT iwrc jbl_patch_from_json(struct jbl *jbl, const char *patchjson);

/**
 * @brief Applies the JSON Merge Patch document `patchjson` (rfc7386) to the document.
 *
 * @param jbl       Target document. Not zero.
 * @param patchjson JSON Merge Patch document text. Not zero.
 */
IW_EXPORT iwrc jbl_merge_patch(struct jbl *jbl, const char *patchjson);

/**
 * @brief Applies the JSON Merge Patch document `patch` (rfc7386) to the document.
 *
 * @param jbl   Target document. Not zero.
 * @param patch Merge patch document. Not zero.
 */
IW_EXPORT iwrc jbl_merge_patch_jbl(struct jbl *jbl, const struct jbl *patch);

IW_EXTERN_C_END;
#endif
