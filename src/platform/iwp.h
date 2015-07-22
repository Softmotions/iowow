#ifndef IWP_H
#define IWP_H

#include "basedefs.h"
#include <stdint.h>
#include <stdio.h>


/**
 * @brief Get current time in milliseconds.
 * 
 * @param [out] time Time returned
 * @return 0 for success, or -1 for failure (in which case errno is set appropriately)
 */
IW_EXPORT int iwp_current_time_ms(int64_t *time);


#endif
