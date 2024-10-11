obj-bin-y += head.o
obj-bin-y += built_in_32.o

obj32 := cmdline.32.o
obj32 += reloc.32.o

nocov-y   += $(obj32)
noubsan-y += $(obj32)
targets   += $(obj32)

obj32 := $(addprefix $(obj)/,$(obj32))

CFLAGS_x86_32 := $(subst -m64,-m32 -march=i686,$(XEN_TREEWIDE_CFLAGS))
$(call cc-options-add,CFLAGS_x86_32,CC,$(EMBEDDED_EXTRA_CFLAGS))
CFLAGS_x86_32 += -Werror -fno-builtin -g0 -msoft-float -mregparm=3
CFLAGS_x86_32 += -nostdinc -include $(filter %/include/xen/config.h,$(XEN_CFLAGS))
CFLAGS_x86_32 += $(filter -I% -O%,$(XEN_CFLAGS)) -D__XEN__

# override for 32bit binaries
$(obj32): CFLAGS_stack_boundary :=
$(obj32): XEN_CFLAGS := $(CFLAGS_x86_32) -fpic

$(obj)/%.32.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)

orphan-handling-$(call ld-option,--orphan-handling=error) := --orphan-handling=error
LDFLAGS_DIRECT-$(call ld-option,--warn-rwx-segments) := --no-warn-rwx-segments
LDFLAGS_DIRECT += $(LDFLAGS_DIRECT-y)
LD32 := $(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT))

$(obj)/build32.final.lds: AFLAGS-y += -DFINAL
$(obj)/build32.other.lds $(obj)/build32.final.lds: $(src)/build32.lds.S
	$(call if_changed_dep,cpp_lds_S)

# link all 32bit objects together
$(obj)/built_in_32.tmp.o: $(obj32)
	$(LD32) -r -o $@ $^

$(obj)/built_in_32.%.bin: $(obj)/build32.%.lds $(obj)/built_in_32.tmp.o
## link bundle with a given layout
	$(LD32) $(orphan-handling-y) -N -T $< -Map $(obj)/built_in_32.$(*F).map -o $(obj)/built_in_32.$(*F).o $(obj)/built_in_32.tmp.o
## extract binaries from object
	$(OBJCOPY) -j .text -O binary $(obj)/built_in_32.$(*F).o $@
	rm -f $(obj)/built_in_32.$(*F).o

# generate final object file combining and checking above binaries
$(obj)/built_in_32.S: $(obj)/built_in_32.other.bin $(obj)/built_in_32.final.bin
	$(PYTHON) $(srctree)/tools/combine_two_binaries \
		--script $(obj)/build32.final.lds \
		--bin1 $(obj)/built_in_32.other.bin \
		--bin2 $(obj)/built_in_32.final.bin \
		--map $(obj)/built_in_32.final.map \
		--exports cmdline_parse_early,reloc \
		--section-header '.section .init.text, "ax", @progbits' \
		--output $@

clean-files := built_in_32.*.bin built_in_32.*.map build32.*.lds
