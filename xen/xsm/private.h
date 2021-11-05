#ifndef XSM_PRIVATE_H
#define XSM_PRIVATE_H

#include <public/xsm/flask_op.h>

long do_flask_op(xen_flask_op_t *op, bool *copyback);

#ifdef CONFIG_COMPAT

#include <compat/xsm/flask_op.h>

int compat_flask_op(compat_flask_op_t *op, bool *copyback);

#endif /* CONFIG_COMPAT */

#endif /* XSM_PRIVATE_H */
