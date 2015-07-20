#include "platform/platform.h"

#if defined(__linux) || defined(__unix)
#include "linux/linux.c"
#else
#error Unsupported platform
#endif
