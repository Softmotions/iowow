#include "iwexfile.h"
#include "log/iwlog.h"
#include "iwcfg.h"

struct IWFS_EXFILE_IMPL {
    IWFS_FILE *file;
};

static const char* _iwfs_exfile_ecodefn(locale_t locale, uint32_t ecode) {
    return 0;
}

iwrc iwfs_exfile_init(void) {
    static int _iwfs_exfile_initialized = 0;
    iwrc rc;
    if (!__sync_bool_compare_and_swap(&_iwfs_exfile_initialized, 0, 1)) {
        return 0; //initialized already
    }
    rc = iwlog_register_ecodefn(_iwfs_exfile_ecodefn);
    return rc;
    return 0;
}
