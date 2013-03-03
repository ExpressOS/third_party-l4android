obj-$(CONFIG_EXPRESSOS) := glue.o

obj-$(CONFIG_EXPRESSOS_DRIVER) += expressos.o

expressos-objs := ipc-stubs.o expressos_main.o venus.o procfs.o ipc.o misc.o
expressos-objs += fs/open.o fs/read_write.o fs/stat.o fs/namei.o fs/ioctl.o
expressos-objs += net.o futex.o mm.o binder.o profiler.o

EXPRESSOS_USERSPACE_INCLUDE_DIR := $(EXPRESSOS_SRC_DIR)/kernel/expressos/native/include

IDL_GEN_C := $(EXPRESSOS_SRC_DIR)/build/scripts/idl_server_c.py
IDL_GEN_H := $(EXPRESSOS_SRC_DIR)/build/scripts/idl_server_h.py
IDL_SRC := expressos-linux.idl

EXTRA_CFLAGS += -I$(src) -I$(EXPRESSOS_USERSPACE_INCLUDE_DIR) -Wextra -Wno-unused-parameter

quiet_cmd_gen_c ?= IDL-C	$@
      cmd_gen_c ?= $(IDL_GEN_C) < $< > $@

quiet_cmd_gen_h ?= IDL-H	$@
      cmd_gen_h ?= $(IDL_GEN_H) < $< > $@

$(src)/ipc-stubs.c: $(src)/$(IDL_SRC) $(IDL_GEN_C) $(src)/ipc-stubs.h
	$(call cmd,gen_c)

$(src)/ipc-stubs.h: $(src)/$(IDL_SRC) $(IDLGEN_H)
	$(call cmd,gen_h)

clean-files += ipc-stubs.c ipc-stubs.h
