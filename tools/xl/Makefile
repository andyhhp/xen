#
# tools/xl/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Wno-format-zero-length -Wmissing-declarations -Wformat-nonliteral
CFLAGS += -fPIC

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)

CFLAGS_XL += $(CFLAGS_libxenlight)
CFLAGS_XL += $(CFLAGS_libxenutil)
CFLAGS_XL += $(CFLAGS_libxenstore)
CFLAGS_XL += -Wshadow

XL_OBJS-$(CONFIG_X86) = xl_psr.o
XL_OBJS = xl.o xl_cmdtable.o xl_sxp.o xl_utils.o $(XL_OBJS-y)
XL_OBJS += xl_parse.o xl_cpupool.o xl_flask.o
XL_OBJS += xl_vtpm.o xl_block.o xl_nic.o xl_usb.o
XL_OBJS += xl_sched.o xl_pci.o xl_vcpu.o xl_cdrom.o xl_mem.o
XL_OBJS += xl_info.o xl_console.o xl_misc.o
XL_OBJS += xl_vmcontrol.o xl_saverestore.o xl_migrate.o
XL_OBJS += xl_vdispl.o xl_vsnd.o xl_vkb.o

$(XL_OBJS): CFLAGS += $(CFLAGS_libxentoollog)
$(XL_OBJS): CFLAGS += $(CFLAGS_XL)
$(XL_OBJS): CFLAGS += -include $(XEN_ROOT)/tools/config.h # libxl_json.h needs it.

.PHONY: all
all: xl

xl: $(XL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(XL_OBJS) $(LDLIBS_libxenutil) $(LDLIBS_libxenlight) $(LDLIBS_libxentoollog) $(LDLIBS_libxenstore) -lyajl $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(BASH_COMPLETION_DIR)
	$(INSTALL_PROG) xl $(DESTDIR)$(sbindir)
	$(INSTALL_DATA) bash-completion $(DESTDIR)$(BASH_COMPLETION_DIR)/xl

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(BASH_COMPLETION_DIR)/xl
	rm -f $(DESTDIR)$(sbindir)/xl

.PHONY: clean
clean:
	$(RM) *.o xl $(DEPS_RM)

distclean: clean


-include $(DEPS_INCLUDE)
