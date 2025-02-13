#ifndef __XEN_STACK_PROTECTOR_H__
#define __XEN_STACK_PROTECTOR_H__

#ifdef CONFIG_STACK_PROTECTOR

void asmlinkage boot_stack_chk_guard_setup(void);

#else

static inline void boot_stack_chk_guard_setup(void) {};

#endif

#endif	/* __XEN_STACK_PROTECTOR_H__ */
