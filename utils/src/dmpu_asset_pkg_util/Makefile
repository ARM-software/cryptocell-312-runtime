SUB_DIRS = oem_key_request icv_key_response oem_asset_package

all: $(foreach sub_dir,$(SUB_DIRS),do_$(sub_dir))

clean: $(foreach sub_dir,$(SUB_DIRS),clean_$(sub_dir))

clean_%:
	@make -C $* clean

do_%:
	@make -C $* 

.PHONY: all clean clean_% do_%

