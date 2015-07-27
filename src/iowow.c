
#include "log/iwlog.h"
#include "iwcfg.h"

iwrc iwfs_init(void);
iwrc iwp_init(void);

iwrc iw_init(void) {
    iwrc rc;
    static int _iw_initialized = 0;

    if (!__sync_bool_compare_and_swap(&_iw_initialized, 0, 1)) {
        return 0; //initialized already
    }

    rc = iwlog_init();
    if (rc) {
        goto finish;
    }
    
    rc = iwp_init();
    if (rc) {
        goto finish;
    }
    
    rc = iwfs_init();
    if (rc) {
        goto finish;
    }
    
finish:
    return rc;
}
