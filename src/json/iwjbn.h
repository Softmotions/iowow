#pragma once
#ifndef IWJBN_H
#define IWJBN_H

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
 * @file iwjbn.h
 * @brief JSON DOM (`struct jbl_node`) representation of a JSON document.
 *
 * This module implements an in-memory JSON document tree (*Document Object Model*) together with
 * the JSON text reader/writer, JSON Patch (rfc6902), JSON Merge Patch (rfc7386) and
 * JSON Pointer (rfc6901) support for it.
 *
 * Unlike the compact `struct jbl` representation (see @ref iwjbl.h) the DOM tree is mutable:
 * nodes can be added, replaced, detached and patched in place. All node allocations are made either
 * in a user supplied `struct iwpool` or, if no pool is given, with `malloc()`, in which case the
 * caller is responsible for releasing the tree.
 *
 * @see iwjbl.h, iwjson.h
 */

#include "iwjson.h"
#include "iwxstr.h"
#include <stdarg.h>

IW_EXTERN_C_START;

/**
 * @brief JSON value with the same memory layout as the value part of `struct jbl_node`.
 *
 * Used to assign/patch a JSON scalar value of a `struct jbl_node` without touching its
 * tree links (`next`, `prev`, `parent`, `key`).
 *
 * @see jbl_node_as_plain_value(), jbl_plain_value_set_node()
 */
struct jbl_plain_value {
  int vsize;         /**< Size of the value buffer for `JBV_STR` values. */
  jbl_type_t type;   /**< Value type. */
  union {
    const char *vptr; /**< String value (`JBV_STR`). */
    bool    vbool;    /**< Boolean value (`JBV_BOOL`). */
    int64_t vi64;     /**< Integer value (`JBV_I64`). */
    double  vf64;     /**< Floating point value (`JBV_F64`). */
  };
};

/**
 * @brief JSON document node.
 *
 * Nodes of a container node (`JBV_OBJECT`, `JBV_ARRAY`) are linked into a doubly linked list
 * by `child`/`next`/`prev`. Siblings are ordered as they appear in the JSON document.
 */
struct jbl_node {
  struct jbl_node *next;   /**< Next sibling node. */
  struct jbl_node *prev;   /**< Previous sibling node. */
  struct jbl_node *parent; /**< Optional parent node. */
  const char      *key;    /**< Node key. Zero for values of JSON arrays. */
  int      klidx;          /**< Length of the `key` in bytes; for array nodes the element index. */
  uint32_t flags;          /**< Utility node flags. Not used by the library itself. */

  // Do not sort/add members after this point (offsetof usage below)
  struct jbl_node *child;  /**< First child of a container node. */
  int vsize;               /**< Size of the string value in bytes. */
  jbl_type_t type;         /**< Node value type. */
  union {
    const char *vptr;      /**< String value (`JBV_STR`). */
    bool    vbool;         /**< Boolean value (`JBV_BOOL`). */
    int64_t vi64;          /**< Integer value (`JBV_I64`). */
    double  vf64;          /**< Floating point value (`JBV_F64`). */
  };
};

/**
 * @brief struct jbl_node visitor context.
 *
 * The `op`, `result` and `pos` members are reserved for the visitor implementation.
 */
typedef struct jbn_vctx {
  struct jbl_node *root; /**< Root node from which the visit started. */
  void *op;              /**< Arbitrary opaque data of the visitor. */
  void *result;          /**< Visitor result placeholder. */
  struct iwpool *pool;   /**< Pool placeholder, its initialization is the responsibility of the creator. */
  int  pos;              /**< Aux position. Not used by the visitor core. */
  bool terminate;        /**< If `true` the document traversal is terminated immediately. */
} JBN_VCTX;

/**
 * @brief Node visitor callback.
 *
 * Invoked for every node of the tree in depth-first order. A call with `lvl == -1` signals the end
 * of the whole document traversal.
 *
 * @param lvl   Nesting level of the visited node, `-1` on traversal end.
 * @param n     Visited node.
 * @param key   Node key, or zero for array elements.
 * @param klidx Node key length, or element index for array elements.
 * @param vctx  Visitor context.
 * @param rc    Error code holder. Set it to a non-zero value to abort the traversal.
 * @return Visitor command: a bitmask of `JBL_VCMD_*` / `JBN_VCMD_DELETE` values.
 */
typedef jbn_visitor_cmd_t (*JBN_VISITOR)(
  int lvl, struct jbl_node *n, const char *key, int klidx, struct jbn_vctx *vctx,
  iwrc *rc);

/**
 * @brief Specification of the JSON to XML markup conversion.
 *
 * @see jbn_as_xml()
 */
struct jbn_as_xml_spec {
  /** JSON printer function. Required. */
  jbl_json_printer printer_fn;

  /** A pointer to the data for JSON printer function */
  void *printer_fn_data;

  /**
   * A tag name which will be used for items in JSON array.
   * Default: `item`.
   */
  const char *array_tag;

  /**
   * A default root tag name.
   * Default: `root`
   */
  const char *root_tag;

  /**
   * If property starts with `attr_prefix` it will
   * be treated as XML attribute.
   *
   * Default: `>`.
   *
   * Example:
   *
   *  {
   *   "name": "John",
   *   ">age": 30
   *  }
   *
   * Will result in:
   *
   *  <root age="30">
   *   <name>John</name>
   *  </root>
   */
  char attr_prefix;

  /**
   * If property is equals to `body_attr` it will
   * be treated as XML tag body.
   *
   * Default: `` (empty string)
   *
   * Example:
   *  {
   *    "": "Tag body",
   *  }
   *
   * Will result in:
   *
   *  <root>Tag body</root>
   *
   */
  char *body_attr;

  /**
   * Priting flags.
   */
  jbl_print_flags_t flags;

  /**
   *  If set the standard XML header will be at the beginning of output:
   *
   *  <?xml version="1.0" encoding="UTF-8"?>
   *
   */
  bool print_xml_header;
};

//--- Values

/**
 * @brief Copies the value part (type and payload) of the node `n` into `out_value`.
 *
 * Tree links and the key of `n` are not copied.
 */
IW_EXPORT void jbl_node_as_plain_value(const struct jbl_node *n, struct jbl_plain_value *out_value);

/**
 * @brief Assigns the value `v` to the node `n`.
 *
 * Only the value part (type and payload) of `n` is replaced; tree links and the key are preserved.
 */
IW_EXPORT void jbl_plain_value_set_node(const struct jbl_plain_value *v, struct jbl_node *n);

//--- Reading

/**
 * @brief Parses JSON text into a new JSON DOM tree.
 *
 * @param json          JSON text to parse. Not zero.
 * @param [out] node    Holder of the parsed root node. Not zero. Set to zero on error.
 * @param pool          Memory pool used for the tree allocations. Optional; if zero `malloc()` is used
 *                      and the tree should be released by the caller.
 * @return Zero on success, or `JBL_ERROR_PARSE_*` on a malformed document.
 */
IW_EXPORT iwrc jbn_from_json(const char *json, struct jbl_node **node, struct iwpool *pool);

/**
 * @brief Parses a JSON-like JavaScript object literal (unquoted keys are allowed) into a JSON DOM tree.
 *
 * @warning Experimental. Does not conform to the ECMAScript specification.
 *
 * @param json          JSON-like text to parse. Not zero.
 * @param [out] node    Holder of the parsed root node. Not zero.
 * @param pool          Memory pool used for the tree allocations. Optional.
 */
IW_EXPORT iwrc jbn_from_js(const char *json, struct jbl_node **node, struct iwpool *pool);

/**
 * @brief Same as jbn_from_json() but takes a `printf()` style format string.
 */
IW_EXPORT iwrc jbn_from_json_printf(
  struct jbl_node **node, struct iwpool *pool, const char *format,
  ...) __attribute__((format(__printf__, 3, 4)));

/**
 * @brief `va_list` variant of jbn_from_json_printf().
 */
IW_EXPORT iwrc jbn_from_json_printf_va(
  struct jbl_node **node, struct iwpool *pool, const char *format, va_list va);

/**
 * @brief Finds a node in the tree `node` pointed by the rfc6901 JSON pointer `path`.
 *
 * @param node      Root of the search tree. Not zero.
 * @param path      rfc6901 JSON pointer. Not zero.
 * @param [out] res Found node holder. Not zero. Set to zero if the path is not found.
 */
IW_EXPORT iwrc jbn_at(struct jbl_node *node, const char *path, struct jbl_node **res);

/**
 * @brief Same as jbn_at() but accepts a pre-parsed JSON pointer.
 *
 * @see jbl_ptr_alloc()
 */
IW_EXPORT iwrc jbn_at2(struct jbl_node *node, struct jbl_ptr *jp, struct jbl_node **res);

/**
 * @brief Looks up a child node of `node` by object `key` or by array `index`.
 *
 * For `JBV_OBJECT` nodes the `key` is used, for `JBV_ARRAY` nodes the `index` is used.
 *
 * @param node      Container node. Not zero.
 * @param key       Child key for object nodes. Ignored for arrays.
 * @param index     Zero based child index for array nodes. Ignored for objects.
 * @param [out] res Found node holder. Not zero. Set to zero if not found.
 * @return Zero on success, or `JBL_ERROR_PATH_NOTFOUND` if the child does not exist.
 */
IW_EXPORT iwrc jbn_get(struct jbl_node *node, const char *key, int index, struct jbl_node **res);

/**
 * @brief Returns the number of the direct children of the node.
 */
IW_EXPORT int jbn_length(struct jbl_node *node);

/**
 * @brief Extracts an integer value from the node.
 *
 * Floating point values are converted by truncation.
 *
 * @param n         Node to read. Not zero.
 * @param [out] out Value holder. Not zero.
 * @return Zero on success, or `IW_ERROR_INVALID_ARGS` if the node holds a non numeric value.
 */
IW_EXPORT iwrc jbn_int_value(struct jbl_node *n, int64_t *out);

/**
 * @brief Extracts a floating point value from the node.
 *
 * Integer values are converted to `double`.
 *
 * @param n         Node to read. Not zero.
 * @param [out] out Value holder. Not zero.
 * @return Zero on success, or `IW_ERROR_INVALID_ARGS` if the node holds a non numeric value.
 */
IW_EXPORT iwrc jbn_double_value(struct jbl_node *n, double *out);

//--- Writing

/**
 * @brief Prints the JSON DOM tree as JSON text.
 *
 * @param node  Tree root. Not zero.
 * @param pt    JSON printer function. Not zero.
 * @param op    User data passed to the printer function.
 * @param pf    JSON printing mode flags.
 *
 * @see jbl_xstr_json_printer(), jbl_fstream_json_printer(), jbl_count_json_printer()
 */
IW_EXPORT iwrc jbn_as_json(struct jbl_node *node, jbl_json_printer pt, void *op, jbl_print_flags_t pf);

/**
 * @brief Serializes the JSON DOM tree into a newly allocated `\0` terminated C string.
 *
 * @param node    Tree root. Not zero.
 * @param pf      JSON printing mode flags.
 * @param [out] out Holder of the allocated string, should be released by `free()`. Not zero.
 */
IW_EXPORT iwrc jbn_as_json_alloc(struct jbl_node *node, jbl_print_flags_t pf, char **out);

/**
 * @brief Prints the JSON DOM tree as an XML markup.
 *
 * @param node Tree root. Not zero.
 * @param spec Conversion specification. Not zero.
 */
IW_EXPORT iwrc jbn_as_xml(struct jbl_node *node, const struct jbn_as_xml_spec *spec);

//--- Modification

/**
 * @brief Clones the `src` JSON DOM tree into a new `targetp` instance.
 *
 * Memory for the cloned tree is allocated by the given `pool` or with `malloc()` if `pool` is zero.
 *
 * @param src       Source tree. Not zero.
 * @param [out] targetp Holder of the cloned tree. Not zero.
 * @param pool      Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_clone(struct jbl_node *src, struct jbl_node **targetp, struct iwpool *pool);

/**
 * @brief Assigns the value of the `from` node to the `target` node.
 *
 * Context elements of the `target` node (`parent`, `next`, `prev`, `key`) are not touched.
 */
IW_EXPORT void jbn_apply_from(struct jbl_node *target, struct jbl_node *from);

/**
 * @brief Resets the value part of the node, keeping its tree links and key.
 *
 * The node becomes a `JBV_NONE` value with no children.
 */
IW_EXPORT void jbn_data(struct jbl_node *node);

/**
 * @brief Appends the `node` to the children of the `parent` container node.
 *
 * For `JBV_ARRAY` parents the element index (`klidx`) of the node is assigned automatically.
 *
 * @param parent Container node. Not zero.
 * @param node   Node to add. Not zero.
 */
IW_EXPORT void jbn_add_item(struct jbl_node *parent, struct jbl_node *node);

/**
 * @brief Creates a string (`JBV_STR`) child node.
 *
 * @param parent   Container node. Not zero.
 * @param key      Child key. Must be given for object parents, may be zero for arrays.
 * @param val      String value. May be zero to create an empty string.
 * @param vlen     Value length in bytes, or a negative value to use `strlen(val)`.
 * @param node_out Optional holder of the created node.
 * @param pool     Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_add_item_str(
  struct jbl_node *parent, const char *key, const char *val, int vlen, struct jbl_node **node_out,
  struct iwpool *pool);

/**
 * @brief Creates a null (`JBV_NULL`) child node.
 *
 * @param parent Container node. Not zero.
 * @param key    Child key. Must be given for object parents, may be zero for arrays.
 * @param pool   Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_add_item_null(struct jbl_node *parent, const char *key, struct iwpool *pool);

/**
 * @brief Creates an integer (`JBV_I64`) child node.
 *
 * @param parent   Container node. Not zero.
 * @param key      Child key. Must be given for object parents, may be zero for arrays.
 * @param val      Integer value.
 * @param node_out Optional holder of the created node.
 * @param pool     Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_add_item_i64(
  struct jbl_node  *parent,
  const char       *key,
  int64_t           val,
  struct jbl_node **node_out,
  struct iwpool    *pool);

/**
 * @brief Creates a floating point (`JBV_F64`) child node.
 *
 * @param parent   Container node. Not zero.
 * @param key      Child key. Must be given for object parents, may be zero for arrays.
 * @param val      Floating point value.
 * @param node_out Optional holder of the created node.
 * @param pool     Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_add_item_f64(
  struct jbl_node  *parent,
  const char       *key,
  double            val,
  struct jbl_node **node_out,
  struct iwpool    *pool);

/**
 * @brief Creates a boolean (`JBV_BOOL`) child node.
 *
 * @param parent   Container node. Not zero.
 * @param key      Child key. Must be given for object parents, may be zero for arrays.
 * @param val      Boolean value.
 * @param node_out Optional holder of the created node.
 * @param pool     Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_add_item_bool(
  struct jbl_node  *parent,
  const char       *key,
  bool              val,
  struct jbl_node **node_out,
  struct iwpool    *pool);

/**
 * @brief Creates a nested object (`JBV_OBJECT`) child node.
 *
 * @param parent Container node. Not zero.
 * @param key    Child key. Must be given for object parents, may be zero for arrays.
 * @param out    Optional holder of the created node.
 * @param pool   Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_add_item_obj(
  struct jbl_node  *parent,
  const char       *key,
  struct jbl_node **out,
  struct iwpool    *pool);

/**
 * @brief Creates a nested array (`JBV_ARRAY`) child node.
 *
 * @param parent Container node. Not zero.
 * @param key    Child key. Must be given for object parents, may be zero for arrays.
 * @param out    Optional holder of the created node.
 * @param pool   Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_add_item_arr(
  struct jbl_node  *parent,
  const char       *key,
  struct jbl_node **out,
  struct iwpool    *pool);

/**
 * @brief Detaches the `child` node from the `parent` container.
 */
IW_EXPORT void jbn_remove_item(struct jbl_node *parent, struct jbl_node *child);

/**
 * @brief Detaches the subtree pointed by the `path` from the `target` node.
 *
 * @return Detached subtree root, or zero if the path is not found.
 */
IW_EXPORT struct jbl_node* jbn_detach(struct jbl_node *target, const char *path);

/**
 * @brief Same as jbn_detach() but accepts a pre-parsed JSON pointer.
 */
IW_EXPORT struct jbl_node* jbn_detach2(struct jbl_node *target, struct jbl_ptr *path);

/**
 * @brief Copies the JSON subtree under `src_path` of `src` into `target` under `target_path`.
 *
 * An existing subtree under `target_path` is replaced by the copied one.
 *
 * @param src                 Source tree. Not zero.
 * @param src_path            Path of the copied subtree. If it is `/` the `src` node itself is cloned.
 * @param target              Target tree. Not zero.
 * @param target_path         Destination path.
 * @param overwrite_on_nulls  If `true` null source values are copied as well.
 * @param no_src_clone        If `true` the source subtree is not cloned into `pool` before the patch is
 *                            applied. Dangerous if the same pool is used for both trees.
 * @param pool                Allocation pool. Not zero.
 */
IW_EXPORT iwrc jbn_copy_path(
  struct jbl_node *src,
  const char      *src_path,
  struct jbl_node *target,
  const char      *target_path,
  bool             overwrite_on_nulls,
  bool             no_src_clone,
  struct iwpool   *pool);

/**
 * @brief Copies a set of values pointed by the zero terminated `paths` array from `src` into
 * the respective paths of `target`.
 *
 * @param src                Source tree. Not zero.
 * @param target             Target tree. Not zero.
 * @param paths              Zero terminated array of zero terminated key paths.
 * @param overwrite_on_nulls If `true` null source values are copied as well.
 * @param no_src_clone       If `true` the source subtrees are not cloned into `pool` before copying.
 * @param pool               Allocation pool. Not zero.
 *
 * @see jbn_copy_path()
 */
IW_EXPORT iwrc jbn_copy_paths(
  struct jbl_node *src,
  struct jbl_node *target,
  const char     **paths,
  bool             overwrite_on_nulls,
  bool             no_src_clone,
  struct iwpool   *pool);

/**
 * @brief Compares two JSON tree nodes.
 *
 * - Primitive JSON values are compared as is.
 * - JSON arrays are compared by values held in the same position of the array.
 * - JSON objects are compared by the corresponding values held under lexicographically sorted keys.
 *
 * @param n1  First node, may be zero.
 * @param n2  Second node, may be zero.
 * @param [out] rcp Error code holder.
 *
 * @return - Non zero if `n1` and `n2` have different types.
 *         - Zero if `n1` and `n2` are equal.
 *         - Greater than zero if `n1` is greater than `n2`.
 *         - Lesser than zero if `n1` is lesser than `n2`.
 */
IW_EXPORT int jbn_compare_nodes(struct jbl_node *n1, struct jbl_node *n2, iwrc *rcp);

/**
 * @brief Compares values pointed by the same `path` in two JSON trees.
 *
 * @param n1     First tree. Not zero.
 * @param n2     Second tree. Not zero.
 * @param path   rfc6901 JSON pointer.
 * @param vtype  If not zero, both values must have this type, otherwise
 *               `JBL_ERROR_TYPE_MISMATCHED` is reported.
 * @param [out] rcp Error code holder.
 * @return Comparison result as in jbn_compare_nodes(), or `-2` on error.
 */
IW_EXPORT int jbn_path_compare(struct jbl_node *n1, struct jbl_node *n2, const char *path, jbl_type_t vtype, iwrc *rcp);

/**
 * @brief Compares values pointed by different paths in two JSON trees.
 *
 * @see jbn_path_compare()
 */
IW_EXPORT int jbn_paths_compare(
  struct jbl_node *n1, const char *n1path, struct jbl_node *n2, const char *n2path, jbl_type_t vtype,
  iwrc *rcp);

/**
 * @brief Compares a string value pointed by `path` with `sv`.
 *
 * @return Comparison result as in jbn_compare_nodes(), or `-2` on error.
 */
IW_EXPORT int jbn_path_compare_str(struct jbl_node *n, const char *path, const char *sv, iwrc *rcp);

/**
 * @brief Compares an integer value pointed by `path` with `iv`.
 *
 * @return Comparison result as in jbn_compare_nodes(), or `-2` on error.
 */
IW_EXPORT int jbn_path_compare_i64(struct jbl_node *n, const char *path, int64_t iv, iwrc *rcp);

/**
 * @brief Compares a floating point value pointed by `path` with `fv`.
 *
 * @return Comparison result as in jbn_compare_nodes(), or `-2` on error.
 */
IW_EXPORT int jbn_path_compare_f64(struct jbl_node *n, const char *path, double fv, iwrc *rcp);

/**
 * @brief Compares a boolean value pointed by `path` with `bv`.
 *
 * @return Comparison result as in jbn_compare_nodes(), or `-2` on error.
 */
IW_EXPORT int jbn_path_compare_bool(struct jbl_node *n, const char *path, bool bv, iwrc *rcp);

//--- Traversal

/**
 * @brief Performs a depth-first traversal of the JSON DOM tree.
 *
 * @param node    Root of the traversal. Zero to start from `vctx->root`.
 * @param lvl     Initial nesting level, zero for a full tree traversal.
 * @param vctx    Visitor context. Not zero.
 * @param visitor Visitor callback. Not zero.
 */
IW_EXPORT iwrc jbn_visit(struct jbl_node *node, int lvl, struct jbn_vctx *vctx, JBN_VISITOR visitor);

/**
 * @brief Performs a post-order depth-first traversal of the JSON DOM tree.
 *
 * The visitor is called for every node after its children have been visited.
 *
 * @param node    Root of the traversal.
 * @param lvl     Initial nesting level, zero for a full tree traversal.
 * @param visitor Visitor callback. Not zero.
 */
IW_EXPORT iwrc jbn_visit2(struct jbl_node *node, int lvl, iwrc (*visitor)(int, struct jbl_node*));

//--- JSON pointer (rfc6901)

/**
 * @brief Parses an rfc6901 JSON pointer.
 *
 * @note The returned structure should be released by `free()`.
 *
 * @param path      JSON pointer string. Not zero.
 * @param [out] jpp Holder of the parsed structure. Not zero.
 */
IW_EXPORT iwrc jbl_ptr_alloc(const char *path, struct jbl_ptr **jpp);

/**
 * @brief Parses an rfc6901 JSON pointer using the given memory pool.
 *
 * @param path      JSON pointer string. Not zero.
 * @param [out] jpp Holder of the parsed structure. Not zero.
 * @param pool      Allocation pool. Not zero.
 */
IW_EXPORT iwrc jbl_ptr_alloc_pool(const char *path, struct jbl_ptr **jpp, struct iwpool *pool);

/**
 * @brief Compares two JSON pointers lexicographically by their nodes.
 */
IW_EXPORT int jbl_ptr_cmp(struct jbl_ptr *p1, struct jbl_ptr *p2);

/**
 * @brief Serializes a JSON pointer back to its text form.
 *
 * @param ptr  JSON pointer. Not zero.
 * @param xstr Output string buffer. Not zero.
 */
IW_EXPORT iwrc jbl_ptr_serialize(struct jbl_ptr *ptr, struct iwxstr *xstr);

//--- Patching

/**
 * @brief Applies the JSON Patch `patch` (rfc6902) to the JSON tree `root`.
 *
 * @param root  Target tree. Not zero.
 * @param patch Array of patch operations. Not zero.
 * @param cnt   Number of patch operations.
 * @param pool  Allocation pool. Not zero.
 */
IW_EXPORT iwrc jbn_patch(struct jbl_node *root, const struct jbl_patch *patch, size_t cnt, struct iwpool *pool);

/**
 * @brief Applies a patch described by the JSON tree `patch` to the JSON tree `root`.
 *
 * If `patch` is a JSON array it is treated as a JSON Patch (rfc6902) document, if it is a JSON object
 * it is treated as a JSON Merge Patch (rfc7386) document.
 *
 * @param root  Target tree. Not zero.
 * @param patch Patch document tree. Not zero.
 * @param pool  Allocation pool. Not zero.
 */
IW_EXPORT iwrc jbn_patch_auto(struct jbl_node *root, struct jbl_node *patch, struct iwpool *pool);

/**
 * @brief Applies the JSON Merge Patch (rfc7386) `patch` to the JSON tree `root`.
 *
 * @param root  Target tree. Not zero.
 * @param patch Patch tree. Not zero.
 * @param pool  Allocation pool. Not zero.
 */
IW_EXPORT iwrc jbn_merge_patch(struct jbl_node *root, struct jbl_node *patch, struct iwpool *pool);

/**
 * @brief Parses the JSON Merge Patch document `patchjson` and applies it to `root`.
 *
 * @param root      Target tree. Not zero.
 * @param patchjson JSON Merge Patch document text. Not zero.
 * @param pool      Allocation pool. Not zero.
 */
IW_EXPORT iwrc jbn_merge_patch_from_json(struct jbl_node *root, const char *patchjson, struct iwpool *pool);

/**
 * @brief Applies the merge patch `val` at the `path` of `root`.
 *
 * @param root  Target tree. Not zero.
 * @param path  rfc6901 JSON pointer of the merge patch target.
 * @param val   Merge patch value. May be zero.
 * @param pool  Allocation pool. Optional.
 */
IW_EXPORT iwrc jbn_merge_patch_path(
  struct jbl_node *root, const char *path, struct jbl_node *val, struct iwpool *pool);

/**
 * @brief Creates a JSON object tree that nests `val` under the `path`.
 *
 * @param path   JSON pointer path. May be zero or `/` for the root.
 * @param val    Value to nest. May be zero.
 * @param pool   Allocation pool. Optional; if zero `malloc()` is used.
 * @param [out] out Holder of the created tree. Not zero.
 */
IW_EXPORT iwrc jbn_merge_patch_create(
  const char *path, struct jbl_node *val, struct iwpool *pool,
  struct jbl_node **out);

IW_EXTERN_C_END;
#endif
