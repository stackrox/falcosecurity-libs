#if defined(__TARGET_ARCH_x86)
#include "x86_64/vmlinux.h"
#elif defined(__TARGET_ARCH_arm64)
#include "aarch64/vmlinux.h"
#elif defined(__TARGET_ARCH_s390)
#include "s390x/vmlinux.h"
#elif defined(__TARGET_ARCH_powerpc)
#include "ppc64le/vmlinux.h"
#endif
