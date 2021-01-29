# Makefile for managing build and installation

# shared library to build
UTIL_ROOT = $(shell pwd)
UTILS_DIR_ROOT = $(UTIL_ROOT)/../../..
UTILS_SCRIPTS_DIRNAME = $(UTIL_ROOT)


DEPENDENCY_ON_EXISTENCE_OF = $(filter-out $(wildcard $(1)), $(1))

INSTALL_LIST = install_scripts

all:   $(INSTALL_LIST)

install_scripts: $(call DEPENDENCY_ON_EXISTENCE_OF,$(UTILS_DIR_ROOT)/bin)  $(call DEPENDENCY_ON_EXISTENCE_OF,$(UTILS_DIR_ROOT)/bin/example)
	@echo Installing scripts for oem_asset_pkg.py.
	@cp $(UTIL_ROOT)/*.py $(UTILS_DIR_ROOT)/bin
	@cp $(UTIL_ROOT)/examples/*.cfg $(UTILS_DIR_ROOT)/bin/example

$(UTILS_DIR_ROOT)/%:
	@echo Creating directory  for dmpu package
	@mkdir $@
