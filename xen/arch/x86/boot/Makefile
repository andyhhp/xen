obj-bin-y += head.o

head-bin-objs := cmdline.o reloc.o

nocov-y += $(head-bin-objs)
noubsan-y += $(head-bin-objs)
targets += $(head-bin-objs)

head-bin-objs := $(addprefix $(obj)/,$(head-bin-objs))

# For .incbin - add $(obj) to the include path and add the dependencies
# manually as they're not included in .d
$(obj)/head.o: AFLAGS-y += -Wa$(comma)-I$(obj)
$(obj)/head.o: $(head-bin-objs:.o=.bin)

CFLAGS_x86_32 := $(subst -m64,-m32 -march=i686,$(XEN_TREEWIDE_CFLAGS))
$(call cc-options-add,CFLAGS_x86_32,CC,$(EMBEDDED_EXTRA_CFLAGS))
CFLAGS_x86_32 += -Werror -fno-builtin -g0 -msoft-float
CFLAGS_x86_32 += -I$(srctree)/include

# override for 32bit binaries
$(head-bin-objs): CFLAGS_stack_boundary :=
$(head-bin-objs): XEN_CFLAGS := $(CFLAGS_x86_32) -fpic

%.bin: %.lnk
	$(OBJCOPY) -j .text -O binary $< $@

%.lnk: %.o $(src)/build32.lds
	$(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT)) -N -T $(filter %.lds,$^) -o $@ $<

clean-files := *.lnk *.bin
