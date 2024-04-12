obj-y += 0f01.o
obj-y += 0fae.o
obj-y += 0fc7.o
obj-y += blk.o
obj-y += decode.o
obj-$(CONFIG_HVM) += fpu.o
obj-y += util.o
obj-y += util-xen.o

ifeq ($(CONFIG_LIVEPATCH),y)
obj-y += decode-lite.o
else
obj-bin-y += decode-lite.init.o
endif
