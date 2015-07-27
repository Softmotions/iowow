#include "iwfile.h"
#include "iwexfile.h"

iwrc iwfs_init(void) {
    iwrc rc = 0;
    IWRC(iwfs_file_init(), rc);
    IWRC(iwfs_exfile_init(), rc);
    return rc;
}
