obj-$(CONFIG_AMD) += amd.o
obj-y += core.o
obj-$(CONFIG_INTEL) += intel.o

obj-bin-$(CONFIG_AMD) += entrysign.init.o
$(obj)/entrysign.o: AFLAGS-y += -Wa$(comma)-I$(srctree)/arch/x86/cpu/microcode
