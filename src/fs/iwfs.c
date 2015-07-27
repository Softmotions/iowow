#include "iwfile.h"

iwrc iwfs_init(void) {
    iwrc rc;
    rc = iwfs_file_init();
    return rc;
}
