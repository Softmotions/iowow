/** @file */

#ifndef IW_FILE
#define IW_FILE

#include "log/iwlog.h"

extern IWLOG_ECODE_FN iwfs_ecode_fn;

/**
 * @enum iwfs_ecode
 * @brief Error codes.
 */
typedef enum {
    _IWFS_ERROR_FS_START = (IW_ERROR_START + 1000UL),
    _IWFS_ERROR_FS_END
} iwfs_ecode;

/**
 * @enum iwfs_omode
 * @brief File open modes
 */
typedef enum {
    IWFS_READ   = 0x01UL,     /**< Open as a reader. */
    IWFS_WRITE  = 0x02UL,     /**< Open as a writer. */
    IWFS_CREATE = 0x04UL,     /**< Writer creating. */
    IWFS_TRUNC  = 0x08UL      /**< Writer truncating. */
} iwfs_omode;

/**
 * @enum iwfs_lockmode
 * @brief File locking mode.
 */
typedef enum {
    IWFS_NOLOCK = 0x01UL, /**< No lock on file. */
    IWFS_RLOCK  = 0x02UL, /**< Acquire read lock on file. */
    IWFS_WLOCK  = 0x04UL, /**< Acquire write lock on file. */
    IWFS_NBLOCK = 0x08UL  /**< Do not block current thread if file have been locked by another process. */
} iwfs_lockmode;

/**
 * @enum iwfs_openstatus
 * @brief Status of an open file operation.
 */
typedef enum {
    IWFS_OPEN_FAIL      = 0x00UL, /**< Open failed. */
    IWFS_OPEN_NEW       = 0x01UL, /**< Open success, new file've been created. */
    IWFS_OPEN_EXISTING  = 0x02UL  /**< Open success, existing file've been opened. */
} iwfs_openstatus;

#define IWFS_DEFAULT_OMODE (IWFS_CREATE)
#define IWFS_DEFAULT_LOCKMODE (IWFS_NOLOCK)

/**
 * @struct IWFS_FILE_OPTS
 * @brief File open options.
 * @see
 */
typedef struct {
    const char      *path;      /**< Required file path. */
    iwfs_omode      open_mode;  /**< File open mode. */
    iwfs_lockmode   lock_mode;  /**< File locking mode. */
} IWFS_FILE_OPTS;

/**
 * @struct IWFS_FILE_STATE
 * @brief File state
 */
typedef struct {
    int is_open;                /**< `1` if file in open state */
    iwfs_openstatus ostatus;    /**< File open status. */
    IWFS_FILE_OPTS opts;        /**< File open options. */
} IWFS_FILE_STATE;

/**
 * @struct IWFS_FILE_SYNC_OPTS
 * @brief Sync file data options.
 * @see int sync(struct IWFS_FILE *f, IWFS_FILE_SYNC_OPTS opts)
 */
typedef struct {
    int fdata_sync; /**< Fie */
} IWFS_FILE_SYNC_OPTS;


struct IWFS_FILE_IMPL;
typedef struct IWFS_FILE_IMPL IWFS_FILE_IMPL;

/**
 * @struct IWFS_FILE
 * @brief Simple file implementation.
 */
typedef struct IWFS_FILE {

    IWFS_FILE_IMPL *impl; /**< Implementation specific data */

#define IWFS_FILE_METHODS(IW_self) \
    int (*write)  (IW_self, uint64_t off, const void *buf, int64_t siz, int64_t *sp); \
    int (*read)   (IW_self, uint64_t off, void *buf, int64_t siz, int64_t *sp); \
    int (*close)  (IW_self); \
    int (*sync)   (IW_self); \
    int (*state)  (IW_self);

    /**
     * @fn int write(struct IWFS_FILE *f, uint64_t off, const void *buf, int64_t siz, int64_t *sp)
     * @brief Write @a buf bytes into the file
     *
     * @param f `struct IWFS_FILE` pointer
     * @param off Offset from start of the file where bytes will write.
     * @param buf Buffer to write.
     * @param siz Number of bytes to write.
     * @param [out] sp Number of bytes actually written
     * @return `0` on success or error code.
     */
    int (*write)(struct IWFS_FILE *f, uint64_t off, const void *buf, int64_t siz, int64_t *sp);

    /**
     * @fn int read(struct IWFS_FILE *f, uint64_t off, void *buf, int64_t siz, int64_t *sp)
     * @brief Read @a siz bytes into @a buf at the specified offset @a off
     *
     * @param f `struct IWFS_FILE` pointer.
     * @param off Offset from start of the file.
     * @param buf Buffer to read into.
     * @param siz [out] sp Number of bytes actually read.
     * @return `0` on success or error code.
     */
    int (*read)(struct IWFS_FILE *f, uint64_t off, void *buf, int64_t siz, int64_t *sp);

    /**
     * @fn int close(struct IWFS_FILE *f)
     * @brief Closes this file.
     *
     * @return `0` on success or error code.
     */
    int (*close)(struct IWFS_FILE *f);

    /**
     * @fn int sync(struct IWFS_FILE *f, const IWFS_FILE_SYNC_OPTS *opts)
     * @brief Sync file data with fs.
     *
     * @param f `struct IWFS_FILE` pointer.
     * @param opts File sync options.
     */
    int (*sync)(struct IWFS_FILE *f, const IWFS_FILE_SYNC_OPTS *opts);

    /**
     * @fn int state(struct IWFS_FILE *f, IWFS_FILE_STATE* state)
     * @brief Return current file state
     *
     * @param f `struct IWFS_FILE` pointer.
     * @param [out] state File state placeholder.
     * @return `0` on success or error code.
     *
     * @see struct IWFS_FILE_STATE
     */
    int (*state)(struct IWFS_FILE *f, IWFS_FILE_STATE* state);

} IWFS_FILE;

/**
 * @brief Open file and initialize the given @a f structure.
 *
 * @param f `struct IWFS_FILE` pointer.
 * @param opts [in] File open options
 */
IW_EXPORT int iwfs_file_open(IWFS_FILE *f,
                             const IWFS_FILE_OPTS *opts);


#endif
