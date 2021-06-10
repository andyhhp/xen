XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-tsx

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)

.PHONY: clean
clean:
	$(RM) -f -- *.o $(TARGET) $(DEPS_RM)

.PHONY: distclean
distclean: clean
	$(RM) -f -- *~

.PHONY: install
install: all

.PHONY: uninstall
uninstall:

CFLAGS += -Werror
CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenguest)
CFLAGS += -I$(XEN_ROOT)/tools/libs/ctrl -I$(XEN_ROOT)/tools/libs/guest
CFLAGS += $(APPEND_CFLAGS)

LDFLAGS += $(LDLIBS_libxenctrl)
LDFLAGS += $(LDLIBS_libxenguest)
LDFLAGS += $(APPEND_LDFLAGS)

test-tsx.o: Makefile

$(TARGET): test-tsx.o
	$(CC) -o $@ $< $(LDFLAGS)

-include $(DEPS_INCLUDE)
