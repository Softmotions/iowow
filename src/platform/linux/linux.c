#include "platform/iwp.h"
#include <time.h>
#include <math.h>


int iwp_current_time_ms(int64_t *time) {
    struct timespec spec;
    if(clock_gettime(CLOCK_REALTIME, &spec) < 0) {
        *time = 0;
        return -1;
    }
    *time = (spec.tv_sec * 1000) + (uint64_t) round(spec.tv_nsec / 1.0e6);
    return 0;
}
