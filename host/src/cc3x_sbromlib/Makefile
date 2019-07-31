HOST_PROJ_ROOT ?= $(shell pwd)/../..
include $(HOST_PROJ_ROOT)/Makefile.defs

CFLAGS_EXTRA += -DCC_TEE -DCC_SB_SUPPORT_IOT
OS =no_os
include project_sbromlib.mk

include $(HOST_PROJ_ROOT)/Makefile.rules

