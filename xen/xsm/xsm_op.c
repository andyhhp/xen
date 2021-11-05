#ifndef COMPAT

#include <xen/guest_access.h>

#include "private.h"

#define ret_t long
#define _copy_to_guest copy_to_guest
#define _copy_from_guest copy_from_guest

#endif /* COMPAT */

ret_t do_xsm_op(XEN_GUEST_HANDLE_PARAM(void) u_flask_op)
{
    xen_flask_op_t op;
    bool copyback = false;
    ret_t rc = -ENOSYS;

    if ( copy_from_guest(&op, u_flask_op, 1) )
        return -EFAULT;

    switch ( op.cmd )
    {
    case FLASK_LOAD ... FLASK_DEVICETREE_LABEL:
        if ( IS_ENABLED(CONFIG_XSM_FLASK) )
            rc = do_flask_op(&op, &copyback);
        break;
    }

    if ( !rc && copyback && copy_to_guest(u_flask_op, &op, 1) )
        rc = -EFAULT;

    return rc;
}

#if defined(CONFIG_COMPAT) && !defined(COMPAT)
#define COMPAT

#undef _copy_to_guest
#define _copy_to_guest copy_to_compat
#undef _copy_from_guest
#define _copy_from_guest copy_from_compat

#define xen_flask_op_t compat_flask_op_t
#undef ret_t
#define ret_t int
#define do_flask_op compat_flask_op
#define do_xsm_op compat_xsm_op

#include "xsm_op.c"
#endif
