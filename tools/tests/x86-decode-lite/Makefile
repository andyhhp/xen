XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-x86-decode-lite

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM)

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	$(RM) -- $(DESTDIR)$(LIBEXEC_BIN)/$(TARGET)

.PHONY: uninstall
uninstall:

vpath %.c ../../../xen/arch/x86/x86_emulate

CFLAGS += $(CFLAGS_xeninclude) -I. -I../../../xen/arch/x86/
CFLAGS += $(APPEND_CFLAGS)

LDFLAGS += $(APPEND_LDFLAGS)

%.o: Makefile

$(TARGET): main.o insns.o decode-lite.o
	$(CC) -o $@ $^ $(LDFLAGS)

-include $(DEPS_INCLUDE)
