#pragma once
#ifndef IWJSON_H
#define IWJSON_H

/**************************************************************************************************
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
 * @file iwjson.h
 * @brief JSON serialization and patching routines. Common definitions.
 *
 * Supported standards:
 *
 *  - [JSON Patch](https://tools.ietf.org/html/rfc6902)
 *  - [JSON Merge patch](https://tools.ietf.org/html/rfc7386)
 *  - [JSON Path specification](https://tools.ietf.org/html/rfc6901)
 *
 * A JSON document can be represented in two different formats:
 *
 *  - @ref JBL `struct jbl` memory compact binary format [Binn](https://github.com/liteserver/binn).
 *    Used for JSON serialization but lacks data modification flexibility.
 *    Implemented by the @ref iwjbl.h module.
 *
 *  - `struct jbl_node` In memory JSON document represented as a tree (DOM). Convenient for
 *    in-place document modification and patching.
 *    Implemented by the @ref iwjbn.h module.
 *
 * This header holds the definitions shared by both representations and, for convenience, pulls in
 * the public headers of both modules.
 */

#include "basedefs.h"
#include <stdbool.h>

IW_EXTERN_C_START;

/**
 * @brief JSON document in the memory compact binary format [Binn](https://github.com/liteserver/binn).
 * @see iwjbl.h
 */
struct jbl;
typedef struct jbl*JBL;

/**
 * @brief JSON document node in the in memory DOM tree representation.
 * @see iwjbn.h
 */
struct jbl_node;
typedef struct jbl_node*JBL_NODE;

/**
 * @brief JSON subsystem error codes.
 *
 * The `JBL_` prefix is historical: the codes are shared by both JSON representations.
 */
typedef enum {
  _JBL_ERROR_START = (IW_ERROR_START + 6000UL),
  JBL_ERROR_INVALID_BUFFER,             /**< Invalid `struct jbl` buffer (JBL_ERROR_INVALID_BUFFER) */
  JBL_ERROR_CREATION,                   /**< Cannot create a `struct jbl` object (JBL_ERROR_CREATION) */
  JBL_ERROR_INVALID,                    /**< Invalid `struct jbl` object (JBL_ERROR_INVALID) */
  JBL_ERROR_PARSE_JSON,                 /**< Failed to parse JSON string (JBL_ERROR_PARSE_JSON) */
  JBL_ERROR_PARSE_UNQUOTED_STRING,      /**< Unquoted JSON string (JBL_ERROR_PARSE_UNQUOTED_STRING) */
  JBL_ERROR_PARSE_INVALID_CODEPOINT,
  /**< Invalid unicode codepoint/escape sequence
     (JBL_ERROR_PARSE_INVALID_CODEPOINT) */
  JBL_ERROR_PARSE_INVALID_UTF8,         /**< Invalid utf8 string (JBL_ERROR_PARSE_INVALID_UTF8) */
  JBL_ERROR_JSON_POINTER,               /**< Invalid JSON pointer (rfc6901) path (JBL_ERROR_JSON_POINTER) */
  JBL_ERROR_PATH_NOTFOUND,              /**< JSON object not matched the path specified (JBL_ERROR_PATH_NOTFOUND) */
  JBL_ERROR_PATCH_INVALID,              /**< Invalid JSON patch specified (JBL_ERROR_PATCH_INVALID) */
  JBL_ERROR_PATCH_INVALID_OP,           /**< Invalid JSON patch operation specified (JBL_ERROR_PATCH_INVALID_OP) */
  JBL_ERROR_PATCH_NOVALUE,              /**< No value specified in JSON patch (JBL_ERROR_PATCH_NOVALUE) */
  JBL_ERROR_PATCH_TARGET_INVALID,
  /**< Could not find target object to set value (JBL_ERROR_PATCH_TARGET_INVALID) */
  JBL_ERROR_PATCH_INVALID_VALUE,        /**< Invalid value specified by patch (JBL_ERROR_PATCH_INVALID_VALUE) */
  JBL_ERROR_PATCH_INVALID_ARRAY_INDEX,
  /**< Invalid array index in JSON patch path
     (JBL_ERROR_PATCH_INVALID_ARRAY_INDEX) */
  JBL_ERROR_NOT_AN_OBJECT,              /**< JSON document is not an object (JBL_ERROR_NOT_AN_OBJECT) */
  JBL_ERROR_TYPE_MISMATCHED,
  /**< Type of the JSON document mismatched user type constraints
     (JBL_ERROR_TYPE_MISMATCHED) */
  JBL_ERROR_PATCH_TEST_FAILED,          /**< JSON patch test operation failed (JBL_ERROR_PATCH_TEST_FAILED) */
  JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED,
  /**< Reached the maximal JSON document nesting level
     (JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED) */
  _JBL_ERROR_END,
} jbl_ecode_t;

/**
 * @brief JSON printing mode flags.
 * @see jbl_as_json(), jbn_as_json()
 */
typedef unsigned int jbl_print_flags_t;
#define JBL_PRINT_PRETTY         ((jbl_print_flags_t) 0x01U)                    ///< Pretty print indented by one space.
#define JBL_PRINT_CODEPOINTS     ((jbl_print_flags_t) 0x02U)                    ///< Print with utf codepoints.
#define JBL_PRINT_PRETTY_INDENT2 ((jbl_print_flags_t) 0x04U | JBL_PRINT_PRETTY) ///< Pretty print indented by two
                                                                                ///  spaces.
#define JBL_PRINT_PRETTY_INDENT4 ((jbl_print_flags_t) 0x08U | JBL_PRINT_PRETTY) ///< Pretty print indented by four
                                                                                ///  spaces.

/**
 * @brief JSON tree visitor commands.
 * @see JBN_VISITOR
 */
typedef unsigned int jbn_visitor_cmd_t;
#define JBL_VCMD_OK          ((jbn_visitor_cmd_t) 0x00U) ///< Continue the traversal.
#define JBL_VCMD_TERMINATE   ((jbn_visitor_cmd_t) 0x01U) ///< Terminate the whole traversal.
#define JBL_VCMD_SKIP_NESTED ((jbn_visitor_cmd_t) 0x02U) ///< Do not descend into the node children.
#define JBN_VCMD_DELETE      ((jbn_visitor_cmd_t) 0x04U) ///< Remove the visited node from the tree.

/**
 * @brief JSON document value type.
 */
typedef enum {
  JBV_NONE = 0, /**< No value. */
  JBV_NULL,     /**< `null` value. */
  JBV_BOOL,     /**< Boolean value. */
  JBV_I64,      /**< Integer value. */
  JBV_F64,      /**< Floating point value. */
  JBV_STR,      /**< String value. */
  JBV_OBJECT,   /**< JSON object container. */
  JBV_ARRAY,    /**< JSON array container. */
} jbl_type_t;

/**
 * @brief JSON Patch operation according to rfc6902.
 */
typedef enum {
  JBP_ADD = 1,    /**< Add a value at the target path. */
  JBP_REMOVE,     /**< Remove the value at the target path. */
  JBP_REPLACE,    /**< Replace the value at the target path. */
  JBP_COPY,       /**< Copy the value from the `from` path to the target path. */
  JBP_MOVE,       /**< Move the value from the `from` path to the target path. */
  JBP_TEST,       /**< Test that the value at the target path is equal to the given one. */
  // Non standard operations
  JBP_INCREMENT,  /**< Increment the numeric value at the target path. */
  JBP_ADD_CREATE, /**< Create intermediate object nodes for missing path segments. */
  JBP_SWAP,       /**< Swap the values of two nodes. */
} jbp_patch_t;

/**
 * @brief JSON Patch operation specification.
 * @see jbl_patch(), jbn_patch()
 */
typedef struct jbl_patch {
  jbp_patch_t      op;     /**< Patch operation. */
  const char      *path;   /**< rfc6901 JSON pointer of the operation target. */
  const char      *from;   /**< rfc6901 JSON pointer of the operation source (`JBP_COPY`, `JBP_MOVE`, `JBP_SWAP`). */
  const char      *vjson;  /**< JSON text of the operation value. */
  struct jbl_node *vnode;  /**< JSON tree of the operation value. */
} JBL_PATCH;

/**
 * @brief Parsed rfc6901 JSON pointer.
 * @see jbl_ptr_alloc()
 */
typedef struct jbl_ptr {
  uint64_t op;      /**< Opaque data associated with the pointer. */
  int      cnt;     /**< Number of path nodes. */
  int      sz;      /**< Size of the allocated structure. */
  char    *n[1];    /**< Path nodes. */
} *JBL_PTR;

/**
 * @brief JSON text printer callback.
 *
 * The callback receives either a `(data, size)` chunk or a `count` of repeated character `ch`.
 *
 * @param data  Data chunk to print, or zero if a repeated character should be printed.
 * @param size  Size of the data chunk, or a negative value to use `strlen(data)`.
 * @param ch    Character to print when `data` is zero.
 * @param count Number of times to print `ch` when `data` is zero.
 * @param op    User data.
 */
typedef iwrc (*jbl_json_printer)(const char *data, int size, char ch, int count, void *op);

/**
 * @brief Formats a floating point value as JSON number.
 *
 * Trailing zeroes of the fractional part are trimmed, the decimal separator is always `.`.
 *
 * @param val       Value to format.
 * @param buf       Output buffer of `IWNUMBUF_SIZE` bytes.
 * @param [out] out_len Length of the produced string.
 */
IW_EXPORT void iwjson_ftoa(long double val, char buf[IWNUMBUF_SIZE], size_t *out_len);

/**
 * @brief JSON printer to a `FILE*` stream, eg: `stderr`, `stdout`.
 *
 * @param op `FILE*` pointer.
 */
IW_EXPORT iwrc jbl_fstream_json_printer(const char *data, int size, char ch, int count, void *op);

/**
 * @brief JSON printer to the extended string buffer `IWXSTR`.
 *
 * @param op `IWXSTR*` pointer.
 */
IW_EXPORT iwrc jbl_xstr_json_printer(const char *data, int size, char ch, int count, void *op);

/**
 * @brief JSON printer that just counts the bytes of the produced JSON text.
 *
 * @param op `int*` pointer to the counter.
 */
IW_EXPORT iwrc jbl_count_json_printer(const char *data, int size, char ch, int count, void *op);

/**
 * @brief Registers the JSON subsystem error codes descriptions.
 *
 * Called by `iowow_init()`. Safe to call multiple times.
 */
IW_EXPORT WUR iwrc jbl_init(void);

IW_EXTERN_C_END;

#include "iwjbn.h"
#include "iwjbl.h"

#endif
