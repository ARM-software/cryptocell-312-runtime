
# Makefile for managing SBU build and installation
ifeq ($(CC_CONFIG_SB_X509_CERT_SUPPORTED),1)
	SUB_DIRS_PREFIX = x509cert
else
	SUB_DIRS_PREFIX = cert
endif

$(info $$SUB_DIRS_PREFIX is [${SUB_DIRS_PREFIX}])

# shared library to build
SBU_ROOT = $(shell pwd)
UTIL_ROOT = $(SBU_ROOT)/../..
SBU_SCRIPTS_DIRNAME = $(SUB_DIRS_PREFIX)_utils
SBU_COMMON_SCRIPTS_DIRNAME = common_cert_lib
SBU_ROOT_DIRNAME = cc3x_boot_cert
COMMON_SCRIPTS_DIRNAME = common

DEPENDENCY_ON_EXISTENCE_OF = $(filter-out $(wildcard $(1)), $(1))

INSTALL_LIST = install_sbu

all:   $(INSTALL_LIST)

clean:
	@echo Cleaning

install_sbu: $(call DEPENDENCY_ON_EXISTENCE_OF,$(UTIL_ROOT)/bin) $(call DEPENDENCY_ON_EXISTENCE_OF,$(UTIL_ROOT)/bin/$(SBU_ROOT_DIRNAME)) $(call DEPENDENCY_ON_EXISTENCE_OF,$(UTIL_ROOT)/bin/$(SBU_ROOT_DIRNAME)/$(SBU_COMMON_SCRIPTS_DIRNAME)) $(call DEPENDENCY_ON_EXISTENCE_OF,$(UTIL_ROOT)/bin/$(COMMON_SCRIPTS_DIRNAME))
	@echo Installing SBU scripts
	@cp $(SBU_ROOT)/hbk_gen_util.py $(SBU_ROOT)/$(SBU_SCRIPTS_DIRNAME)
	@cp $(SBU_ROOT)/$(SBU_SCRIPTS_DIRNAME)/*.py $(UTIL_ROOT)/bin
	@cp $(SBU_ROOT)/$(SBU_COMMON_SCRIPTS_DIRNAME)/*.py $(UTIL_ROOT)/bin/$(SBU_ROOT_DIRNAME)/$(SBU_COMMON_SCRIPTS_DIRNAME)
	@cp $(SBU_ROOT)/../$(COMMON_SCRIPTS_DIRNAME)/*.py $(UTIL_ROOT)/bin/$(COMMON_SCRIPTS_DIRNAME)
	@cp $(SBU_ROOT)/../proj.cfg $(UTIL_ROOT)/bin

$(UTIL_ROOT)/%:
	@echo Creating directory $@
	@mkdir $@


.PHONY: install_sbu clean


