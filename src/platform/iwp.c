#include "platform/iwp.h"
#include "log/iwlog.h"

#if defined(__linux) || defined(__unix)
#include "linux/linux.c"
#else
#error Unsupported platform
#endif

iwrc iwp_init(void) {
    return 0;
}
