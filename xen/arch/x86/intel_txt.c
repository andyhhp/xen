#include <xen/compiler.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/init.h>

bool __initdata slaunch_active;

static void __maybe_unused compile_time_checks(void)
{
    BUILD_BUG_ON(sizeof(slaunch_active) != 1);
}
