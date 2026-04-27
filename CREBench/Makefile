ALL_SUBDIRS := $(shell find . -maxdepth 1 -type d ! -name '.')
EXCLUDE_DIRS := Classic
SUBDIRS := $(filter-out $(addprefix ./,$(EXCLUDE_DIRS)),$(ALL_SUBDIRS))


all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ challenge

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done

.PHONY: all clean $(SUBDIRS)
