SUB_DIRS = oem_key_request icv_key_response oem_asset_package

all: $(foreach sub_dir,$(SUB_DIRS),do_$(sub_dir))

do_%:
	@make -C $* 

clean:
	@echo Cleaning

.PHONY: all do_% clean

