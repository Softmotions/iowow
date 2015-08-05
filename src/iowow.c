/**************************************************************************************************
 *  IOWOW library
 *  Copyright (C) 2012-2015 Softmotions Ltd <info@softmotions.com>
 *
 *  This file is part of IOWOW.
 *  IOWOW is free software; you can redistribute it and/or modify it under the terms of
 *  the GNU Lesser General Public License as published by the Free Software Foundation; either
 *  version 2.1 of the License or any later version. IOWOW is distributed in the hope
 *  that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *  You should have received a copy of the GNU Lesser General Public License along with IOWOW;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 *  Boston, MA 02111-1307 USA.
 *************************************************************************************************/

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
