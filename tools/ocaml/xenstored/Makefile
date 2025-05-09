XEN_ROOT = $(CURDIR)/../../..
OCAML_TOPLEVEL = $(CURDIR)/..
include $(OCAML_TOPLEVEL)/common.make

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS-$(CONFIG_SYSTEMD)  += $(CFLAGS_xeninclude)

CFLAGS  += $(CFLAGS-y)
CFLAGS  += $(APPEND_CFLAGS)
LDFLAGS += $(LDFLAGS-y)
LDFLAGS += $(APPEND_LDFLAGS)

OCAMLINCLUDE += \
	-I $(OCAML_TOPLEVEL)/libs/xb \
	-I $(OCAML_TOPLEVEL)/libs/mmap \
	-I $(OCAML_TOPLEVEL)/libs/xc \
	-I $(OCAML_TOPLEVEL)/libs/eventchn \
	-I $(OCAML_TOPLEVEL)/libs/xsd_glue

LIBS = syslog.cma syslog.cmxa poll.cma poll.cmxa
syslog_OBJS = syslog
syslog_C_OBJS = syslog_stubs
poll_OBJS = poll
poll_C_OBJS = select_stubs
OCAML_LIBRARY = syslog poll

LIBS += systemd.cma systemd.cmxa
systemd_OBJS = systemd
systemd_C_OBJS = systemd_stubs
OCAML_LIBRARY += systemd

LIBS_systemd += $(LDFLAGS-y)

OBJS = paths \
	define \
	stdext \
	trie \
	config \
	packet \
	logging \
	quota \
	perms \
	symbol \
	utils \
	store \
	disk \
	transaction \
	event \
	domain \
	domains \
	connection \
	connections \
	history \
	parse_arg \
	process \
	poll \
	xenstored

INTF = symbol.cmi trie.cmi syslog.cmi systemd.cmi poll.cmi

XENSTOREDLIBS = \
	unix.cmxa \
	dynlink.cmxa \
	-ccopt -L -ccopt . syslog.cmxa \
	-ccopt -L -ccopt . systemd.cmxa \
	-ccopt -L -ccopt . poll.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/mmap $(OCAML_TOPLEVEL)/libs/mmap/xenmmap.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/eventchn $(OCAML_TOPLEVEL)/libs/eventchn/xeneventchn.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xc $(OCAML_TOPLEVEL)/libs/xc/xenctrl.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xb $(OCAML_TOPLEVEL)/libs/xb/xenbus.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xsd_glue $(OCAML_TOPLEVEL)/libs/xsd_glue/plugin_interface_v1.cmxa \
	-ccopt -L -ccopt $(XEN_ROOT)/tools/libs/ctrl

PROGRAMS = oxenstored

oxenstored_LIBS = $(XENSTOREDLIBS)
# use ocamldep to figure out link order, otherwise the Makefile would have
# to be continously adjusted for security patches that introduce new
# dependencies between files
oxenstored_MLSORTED = $(shell $(OCAMLDEP) -sort $(OBJS:=.ml))
oxenstored_OBJS = $(oxenstored_MLSORTED:.ml=)

OCAML_PROGRAM = oxenstored

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) oxenstored $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	$(INSTALL_DATA) oxenstored.conf $(DESTDIR)$(XEN_CONFIG_DIR)

uninstall:
	rm -f $(DESTDIR)$(XEN_CONFIG_DIR)/oxenstored.conf
	rm -f $(DESTDIR)$(sbindir)/oxenstored

include $(OCAML_TOPLEVEL)/Makefile.rules
