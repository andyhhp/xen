
# the base of where these containers will appear
REGISTRY := registry.gitlab.com/xen-project/xen
CONTAINERS := $(filter-out yocto/%,$(subst .dockerfile,,$(wildcard */*.dockerfile)))
CONTAINERS_EXTRA =
DOCKER_CMD ?= docker

help:
	@echo "Builds containers for building Xen based on different distros"
	@echo "To build one run 'make DISTRO/VERSION'. Available containers:"
	@$(foreach file,$(sort $(CONTAINERS)),echo $(file);)
	@echo "Extra containers (not built using make all):"
	@$(foreach file,$(sort $(CONTAINERS_EXTRA)),echo $(file);)
	@echo "To push container builds, set the env var PUSH"

include yocto/yocto.inc

# Find out if we are running Podman, if not is likely docker.
is-docker = $(if $(filter Podman,$(shell $(DOCKER_CMD) version)),,1)

# Find out the docker API version is at least 1.46. We exploit `sort -V` to
# compare the versions at it can sort by version.
docker-api-version = $(shell $(DOCKER_CMD) version -f '{{.Client.APIVersion}}')
docker-min-version = $(firstword $(shell printf "1.46\n$(docker-api-version)" | sort -V))
docker-have-push-platform = $(if $(filter 1.46,$(docker-min-version)),1)

# check if we can use `X push --platform`.
# `podman push` doesn't support --platform.
# `docker` only have it on recent version.
builder-have-push-platform = $(and $(is-docker),$(docker-have-push-platform))

%: %.dockerfile ## Builds containers
	set -xe; \
	$(if $(builder-have-push-platform), \
	    platform=$$(sed -n '/^FROM/{s/.*\(--platform=[^ ]*\) .*/\1/p;q}' $<); ) \
	img="$(REGISTRY)/$(@D):$(@F)"; \
	$(DOCKER_CMD) build --pull $$platform -t $$img -f $< $(<D); \
	if [ ! -z $${PUSH+x} ]; then \
		$(DOCKER_CMD) push $$platform $$img; \
	fi

.PHONY: all clean
all: $(CONTAINERS)

# Remove generated dockerfiles for yocto
clean:
	rm -f yocto/*.dockerfile

define CLEAN_RULE
.PHONY: clean-$(1)
clean-$(1):
	if [ -n "$$$$($(DOCKER_CMD) image ls -q $(REGISTRY)/$(subst /,:,$(1)))" ]; then \
		$(DOCKER_CMD) image rm $(REGISTRY)/$(subst /,:,$(1)); \
	fi

endef

$(eval $(foreach img,$(CONTAINERS) $(CONTAINERS_EXTRA),$(call CLEAN_RULE,$(img))))
