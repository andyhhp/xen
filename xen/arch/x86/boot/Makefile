obj-bin-y += head.o cbundle.o

head-bin-objs := cmdline.o reloc.o

nocov-y   += $(head-bin-objs)
noubsan-y += $(head-bin-objs)
targets   += $(head-bin-objs)

head-bin-objs := $(addprefix $(obj)/,$(head-bin-objs))

$(obj)/head.o: AFLAGS-y += -Wa$(comma)-I$(obj)

CFLAGS_x86_32 := $(subst -m64,-m32 -march=i686,$(XEN_TREEWIDE_CFLAGS))
$(call cc-options-add,CFLAGS_x86_32,CC,$(EMBEDDED_EXTRA_CFLAGS))
CFLAGS_x86_32 += -Werror -fno-builtin -g0 -msoft-float -mregparm=3
CFLAGS_x86_32 += -nostdinc -include $(filter %/include/xen/config.h,$(XEN_CFLAGS))
CFLAGS_x86_32 += $(filter -I%,$(XEN_CFLAGS))

# override for 32bit binaries
$(head-bin-objs): CFLAGS_stack_boundary :=
$(head-bin-objs): XEN_CFLAGS := $(CFLAGS_x86_32) -fpic

LDFLAGS_DIRECT-$(call ld-option,--warn-rwx-segments) := --no-warn-rwx-segments
LDFLAGS_DIRECT += $(LDFLAGS_DIRECT-y)

$(obj)/build32.final.lds: AFLAGS-y += -DFINAL
$(obj)/build32.other.lds $(obj)/build32.final.lds: $(src)/build32.lds.S
	$(call if_changed_dep,cpp_lds_S)

%.bin: %.lnk
	$(OBJCOPY) -j .text -O binary $< $@

$(obj)/cbundle.o: $(head-bin-objs) $(obj)/build32.other.lds $(obj)/build32.final.lds
## link all object files together
	$(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT)) -r -o $(obj)/cbundle.tmp.o $(head-bin-objs)
## link twice with 2 different layouts
	$(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT)) --orphan-handling=error -N -T $(obj)/build32.other.lds -o $@.1.o $(obj)/cbundle.tmp.o
	$(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT)) --orphan-handling=error -N -T $(obj)/build32.final.lds -Map $(obj)/cbundle.map -o $@.2.o $(obj)/cbundle.tmp.o
## extract binaries from them
	$(OBJCOPY) -j .text -O binary $@.1.o $@.1.bin
	$(OBJCOPY) -j .text -O binary $@.2.o $@.2.bin
## generate final assembly file combining and checking above binaries
	$(PYTHON) $(srctree)/tools/make_output \
		--script $(obj)/build32.final.lds \
		--bin1 $@.1.bin --bin2 $@.2.bin \
		--map $(obj)/cbundle.map --exports cmdline_parse_early,reloc \
		--section-header '.section .init.text, "ax", @progbits' \
		--output $(obj)/cbundle.s
	$(CC) -c $(obj)/cbundle.s -o $@.tmp
	rm -f $(obj)/cbundle.tmp.o $@.1.o $@.2.o $@.1.bin $@.2.bin $(obj)/cbundle.map $(obj)/cbundle.s $@
	mv $@.tmp $@

clean-files := *.lnk *.bin
