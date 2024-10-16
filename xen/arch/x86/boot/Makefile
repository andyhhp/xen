obj-bin-y += head.o
obj-bin-y += built-in-32.o

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

text_gap := 0x010200
text_diff := 0x408020

$(obj)/build32.other.lds: AFLAGS-y += -DGAP=$(text_gap) -DTEXT_DIFF=$(text_diff)
$(obj)/build32.final.lds: AFLAGS-y += -DGAP=$(text_gap) -DTEXT_DIFF=$(text_diff) -DFINAL
$(obj)/build32.other.lds $(obj)/build32.final.lds: $(src)/build32.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

targets += build32.final.lds build32.other.lds

# link all 32bit objects together
$(obj)/built-in-32.tmp.o: $(obj32)
	$(LD32) -r -o $@ $^

# link bundle with a given layout and extract a binary from it
$(obj)/built-in-32.%.bin: $(obj)/build32.%.lds $(obj)/built-in-32.tmp.o
	$(LD32) $(orphan-handling-y) -N -T $< -Map $(@:bin=map) -o $(@:bin=o) $(filter %.o,$^)
	$(OBJCOPY) -j .text -O binary $(@:bin=o) $@
	rm -f $(@:bin=o)

# generate final object file combining and checking above binaries
$(obj)/built-in-32.S: $(obj)/built-in-32.other.bin $(obj)/built-in-32.final.bin \
	$(srctree)/tools/combine_two_binaries.py
	$(PYTHON) $(srctree)/tools/combine_two_binaries.py \
		--gap=$$(( $(text_gap) )) --text-diff=$$(( $(text_diff) )) \
		--script $(obj)/build32.final.lds \
		--bin1 $(obj)/built-in-32.other.bin \
		--bin2 $(obj)/built-in-32.final.bin \
		--map $(obj)/built-in-32.final.map \
		--exports cmdline_parse_early,reloc \
		--output $@

clean-files := built-in-32.*.bin built-in-32.*.map build32.*.lds
