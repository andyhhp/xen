obj-bin-y += head.o
head-srcs := cmdline.S reloc.S

nocov-y += $(head-srcs:.S=.o)
noubsan-y += $(head-srcs:.S=.o)
targets += $(head-srcs:.S=.o)

head-srcs := $(addprefix $(obj)/, $(head-srcs))

# For .incbin - add $(obj) to the include path and add the dependencies
# manually as they're not included in .d
$(obj)/head.o: AFLAGS-y += -Wa$(comma)-I$(obj)
$(obj)/head.o: $(head-srcs:.S=.bin)

CFLAGS_x86_32 := $(subst -m64,-m32 -march=i686,$(XEN_TREEWIDE_CFLAGS))
$(call cc-options-add,CFLAGS_x86_32,CC,$(EMBEDDED_EXTRA_CFLAGS))
CFLAGS_x86_32 += -Werror -fno-builtin -g0 -msoft-float
CFLAGS_x86_32 += -I$(srctree)/include

# override for 32bit binaries
$(head-srcs:.S=.o): CFLAGS_stack_boundary :=
$(head-srcs:.S=.o): XEN_CFLAGS := $(CFLAGS_x86_32) -fpic

%.bin: %.lnk
	$(OBJCOPY) -j .text -O binary $< $@

%.lnk: %.o $(src)/build32.lds
	$(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT)) -N -T $(filter %.lds,$^) -o $@ $<

clean-files := cmdline.S reloc.S *.lnk *.bin
